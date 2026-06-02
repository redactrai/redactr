# Redactr

A local HTTPS forward proxy that filters PII and secrets from AI coding tools, plus an optional hosted control plane that manages a fleet of those proxies across a team. Three Go binaries, no external runtime dependencies (a container runtime is required only for the sandboxed agent front doors).

Redactr sits between your AI tools (Claude Code, GitHub Copilot, ChatGPT Codex) and their APIs, scanning every outbound request through a multi-layer pipeline that catches emails, SSNs, API keys, secrets, and other sensitive data before it leaves your machine. In **team mode** it also launches each AI agent inside a hardened container whose egress is force-routed through the proxy, so redaction can't be bypassed and a malicious dependency can't reach the host.

## Components

| Binary | Role |
|--------|------|
| `redactr` | The desktop client: a local daemon (proxy + scanner + dashboard + control socket) and the user-facing subcommands (`claude`, `code`, `enroll`, `shell`, `tray`, …). |
| `redactr-server` | The hosted **control plane**: multi-tenant orgs/devices, device enrollment, signed policy distribution, monitoring ingestion, image build/sign pipeline, and the admin dashboard. Sees only metadata — never traffic, code, or redacted values. |
| `redactr-mcp-wrap` | Wraps a Desktop-app MCP server, scanning its stdio JSON-RPC; with `--container`, runs the MCP server inside a redactr container too. |

```bash
make build      # builds bin/redactr, bin/redactr-mcp-wrap, bin/redactr-server
```

## Quick Start — standalone (single machine)

No server required. The daemon redacts everything routed through it.

```bash
make build
./bin/redactr                 # daemon: proxy + dashboard :9080 + admin/metrics :9090
```

Then bind a tool to the proxy:

```bash
./bin/redactr shell           # a shell with HTTPS_PROXY + CA env exported — anything launched here is scanned
#   or, for a one-off process:
export HTTPS_PROXY=http://localhost:<proxy-port>
export NODE_EXTRA_CA_CERTS=~/.redactr/certs/ca.crt
claude
```

The proxy port is printed at startup and shown on the dashboard at `http://localhost:9080`.

## Quick Start — team mode (control plane + sandboxed agents)

```bash
# 1. On the server host
go build -o bin/redactr-server ./cmd/redactr-server
REDACTR_ADMIN_KEY=$(openssl rand -base64 24) ./bin/redactr-server   # listens :8080
#    Open http://<host>:8080/ (the admin key gates the dashboard),
#    create an org, and mint an enrollment token.

# 2. On each client machine
./bin/redactr                                                       # daemon
./bin/redactr enroll --server http://<host>:8080 --token <enrollment-token>

# 3. Launch agents — now policy-synced and sandboxed
./bin/redactr claude            # Claude Code inside a hardened container, egress forced through the proxy
./bin/redactr code ./project    # VS Code Dev Container (sandboxes Copilot + every VS Code AI plugin)
```

`redactr claude|codex|copilot` requires a container runtime (Docker, Podman, or Colima). It launches the agent inside a container built from the org's signed policy image (`ref@digest`), with the CA mounted read-only, proxy env injected, a default-deny egress firewall that DNATs ports 80/443 to the host proxy, and `--cap-drop ALL` hardening. `redactr shell` remains the host-bind path when you don't want a container.

### Front doors (how each tool gets protected)

| Tool surface | Command | Mechanism |
|--------------|---------|-----------|
| CLI agents (Claude Code, Codex, Copilot CLI) | `redactr claude` / `codex` / `copilot` | Hardened container, egress force-routed to the proxy |
| VS Code plugins (Copilot, Claude, …) | `redactr code <project>` | Generates `.devcontainer/devcontainer.json` so the extension host runs in a redactr container |
| Desktop-app MCP servers | `redactr-mcp-wrap [--container] <cmd>` | Scans the MCP stdio JSON-RPC stream; optionally containerizes the server |
| Any process | `redactr shell` / manual env | Host shell bound to the proxy via `HTTPS_PROXY` + CA env |

## Dashboards

- **Client dashboard** (`http://localhost:9080`): proxy toggle, redaction metrics, 24-hour trend, intercepted tools, safety recommendations, per-entry redaction logs (which layer caught what and why), and live config editing.
- **Server admin dashboard** (`http://<host>:8080/`, admin-key gated): orgs, device registry, enrollment-token minting, policy editor (denylist + image pinning), fleet monitoring events, and the Dockerfile build/sign image pipeline.

## Architecture

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

Privacy invariant: the control plane only ever receives metadata (session/runaway events, device attribution) — never request bodies, source code, connection strings, env values, or redacted content.

## Scanning Layers

| Layer | What It Catches | Speed |
|-------|----------------|-------|
| Regex | Emails, SSNs, credit cards, phone numbers, AWS keys, JWTs, connection strings, IP addresses | ~100ns |
| Entropy | High-entropy tokens, base64 secrets, random API keys that don't match fixed patterns | ~200ns |
| GLiNER | Names, addresses, dates of birth (requires Python sidecar) | ~50ms |
| Context Gate | Business-specific rules (extensible stub) | ~0ns |

## File Blocking

These file types are blocked by default — their contents never reach AI providers:

- `.env` — environment variables with secrets
- `.tfstate` — Terraform state with infrastructure credentials
- `.pem`, `.key`, `.p12`, `.pfx` — private keys and certificates

## Running Tests

```bash
# Unit tests (62 tests)
make test

# Integration test (full proxy pipeline)
go test ./test/integration/ -v -tags=integration

# Benchmarks
make benchmark

# End-to-end proxy benchmark against ai4privacy/pii-masking-300k dataset
go test ./benchmarks/ -v -tags=benchmark -run TestProxyE2EBenchmark
```

## Benchmark Results

Tested against **ai4privacy/pii-masking-300k** dataset (56 English samples, 433 PII entities) running the full proxy pipeline end-to-end (not isolated components).

### Full Pipeline (Regex + Entropy + GLiNER)

| Metric | Value |
|--------|-------|
| Precision | **79.5%** |
| Recall | **68.8%** |
| F1 Score | **73.8** |
| Avg Latency per Request | **91.5ms** |
| False Positives | 77 (mostly GLiNER over-detecting PERSON/ORG) |

### Regex-Only (no GLiNER sidecar)

| Metric | Value |
|--------|-------|
| Precision | **98.6%** |
| Recall (regex-detectable PII) | **90.9%** |
| Avg Latency per Request | **0.02ms** |
| False Positives | 3 |

### Per-Layer Detection

| Layer | Caught | False Positives | Precision | What It Catches |
|-------|--------|-----------------|-----------|-----------------|
| **Regex** | 141 | 2 | **98.6%** | Emails, SSNs, phones, IPs, IDs, passports, secrets |
| **GLiNER** | 154 | 74 | 67.5% | Names, addresses, DOBs, passports, titles |
| **Entropy** | 3 | 1 | 75.0% | High-randomness tokens |

### What We Catch

| PII Type | Total | Caught | Rate | Primary Layer |
|----------|-------|--------|------|---------------|
| EMAIL | 23 | 23 | **100%** | regex |
| SSN / Social Security | 27 | 27 | **100%** | regex |
| Phone Numbers (US/UK/NL/intl) | 32 | 32 | **100%** | regex |
| IP Addresses (v4 + v6) | 5 | 5 | **100%** | regex |
| Driver's License | 13 | 13 | **100%** | regex + gliner |
| Person Names | 70 | 66 | **94.3%** | gliner |
| ID Cards | 42 | 40 | **95.2%** | regex |
| Passport Numbers | 18 | 17 | **94.4%** | regex + gliner |
| Addresses | 76 | 33 | **43.4%** | gliner |
| Dates/Times | 45 | 11 | **24.4%** | gliner |

### False Positives Breakdown

| Type | Count | Layer | Cause |
|------|-------|-------|-------|
| PERSON | 46 | gliner | Over-detects generic words like "applicants", "[Your Name]" |
| ORGANIZATION | 16 | gliner | Detects org names that aren't PII in context |
| PHONE | 4 | regex | Number strings matching phone patterns |
| ADDRESS/EMAIL/DL | 10 | gliner | Partial matches on contextual text |
| ENTROPY-SECRET | 1 | entropy | "forward-thinking" flagged |

### Interpretation

The 3-layer pipeline catches **298 of 433 PII entities (68.8% recall)**. Regex handles structured PII (emails, SSNs, phones) with near-perfect 98.6% precision. GLiNER adds critical coverage for names and addresses that regex cannot detect, catching 154 additional entities at the cost of 74 false positives — these are mostly benign over-detections of generic words as person names. The combined F1 of 73.8 reflects a strong balance between catching real PII and avoiding unnecessary redaction.

## Configuration

Config lives at `~/.redactr/config.yaml` or is editable from the dashboard.

```yaml
proxy:
  enabled: false
  intercepted_domains:
    - api.anthropic.com
    - api.openai.com
    - api.githubcopilot.com
    - copilot-proxy.githubusercontent.com
  blocked_domains: []

scanning:
  regex_enabled: true
  entropy_enabled: true
  entropy_threshold: 4.5
  gliner_enabled: true
  cache_max_size: 10000

file_blocking:
  blocked_extensions: [".env", ".tfstate", ".pem", ".key", ".p12", ".pfx"]
  content_patterns_enabled: true

hooks:
  enabled: false
  claude_code: false
```

## Project Structure

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
  domain/                 — Domain intercept/block filtering
  fileblock/              — File extension and content blocking
  firewall/               — OS firewall rules (macOS pf, Linux iptables, Windows netsh)
  lifecycle/              — Singleton lock + orphan reaping
  hooks/                  — Claude Code hooks + safecmd allowlist
  mcpwrap/                — MCP JSON-RPC message scanning
  proxy/                  — goproxy HTTPS MITM forward proxy
  redactor/               — [REDACTED-LABEL] replacement engine
  scanner/                — 4-layer scanning pipeline
    regex/                — Layer 1: pattern matching
    entropy/              — Layer 2: Shannon entropy detection
    gliner/               — Layer 3: GLiNER ML model client
    contextgate/          — Layer 4: business rules stub
  sidecar/                — Python process manager for GLiNER
  store/                  — BoltDB scan report persistence
  server/                 — Control plane (redactr-server):
    store/                — Embedded pure-Go SQLite (orgs/devices/tokens/policies/events/images)
    auth/                 — Device bearer tokens, enrollment, RequireDevice/RequireAdmin
    keys/                 — Load-or-generate server ECDSA keypair
    httpapi/              — Routes + embedded admin dashboard (dashboard/)
    imagebuild/           — Dockerfile build → push → cosign-sign orchestration
build/sandbox/            — redactr-base image + container entrypoint (default-deny egress)
sidecar/gliner/           — Python Flask server for GLiNER model
benchmarks/               — Benchmark harness + ai4privacy test data
docs/superpowers/         — v2 architecture spec, subsystem designs, and implementation plans
```

## Server configuration (`redactr-server`)

Configured via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `REDACTR_SERVER_ADDR` | `:8080` | Listen address |
| `REDACTR_SERVER_DB` | `./redactr-server.db` | SQLite path |
| `REDACTR_SERVER_KEY_DIR` | `./keys` | ECDSA signing keypair location |
| `REDACTR_ADMIN_KEY` | _generated + logged_ | Admin API / dashboard key (set it to persist across restarts) |
| `REDACTR_REGISTRY` | _unset_ | Enables the image pipeline; registry base for built images |
| `REDACTR_COSIGN_KEY` | `./keys/cosign.key` | cosign key for image signing |

The image build pipeline (`REDACTR_REGISTRY` set) additionally requires `docker` and `cosign` on the server host.
