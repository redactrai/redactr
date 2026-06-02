# Redactr - AI Privacy Proxy

## Overview

Redactr is a local HTTPS forward proxy that filters PII, secrets, and sensitive information from reaching AI coding tools (Claude Code, GitHub Copilot, ChatGPT Codex). Everything runs locally — no data leaves the machine unscanned. A single Go binary with an embedded Next.js dashboard serves as both the proxy engine and the control plane.

## Architecture

**Approach:** Monolithic Go process + Python sidecar for GLiNER model inference.

Single Go binary handles: HTTPS proxy, scanning pipeline, BoltDB storage, REST/WebSocket API, embedded static dashboard. The only external process is a Python sidecar for GLiNER PII detection, spawned and managed by the Go binary.

### Monorepo Structure

```
redactr/
├── cmd/
│   ├── redactr/                 # entry point — starts proxy, dashboard, sidecar manager
│   └── redactr-mcp-wrap/        # MCP stdin/stdout wrapper binary
├── internal/
│   ├── proxy/                   # goproxy-based HTTPS forward proxy
│   ├── scanner/                 # scanning pipeline coordinator
│   │   ├── regex/               # layer 1: regex patterns
│   │   ├── entropy/             # layer 2: entropy detection
│   │   ├── gliner/              # layer 3: GLiNER sidecar client
│   │   └── contextgate/         # layer 4: future extension point (stub)
│   ├── redactor/                # applies dynamic [REDACTED-X] labels
│   ├── fileblock/               # .env/.tfstate filename + content detection
│   ├── domain/                  # domain restriction logic
│   ├── config/                  # runtime config (dashboard-controlled, persisted)
│   ├── store/                   # BoltDB log storage
│   ├── sidecar/                 # GLiNER Python process lifecycle manager
│   ├── api/                     # REST/WebSocket API for dashboard
│   ├── mcpwrap/                 # MCP JSON-RPC interception logic
│   ├── firewall/                # OS-level provider URL blocking (pf/iptables/netsh)
│   └── hooks/                   # Claude Code hook configuration manager
├── web/                         # Next.js dashboard source
│   └── ...
├── sidecar/
│   └── gliner/                  # Python sidecar: GLiNER model loading, inference server
│       ├── server.py
│       └── requirements.txt
├── hooks/
│   └── claude/                  # Claude Code hook scripts for safecmd
├── benchmarks/                  # marketing-only synthetic data tests
│   ├── datasets/                # synthetic test data (gitignored, downloaded on demand)
│   ├── runner.go                # benchmark harness
│   ├── results/                 # generated reports
│   └── README.md
├── configs/
│   └── default.yaml             # default config (built-in regex patterns, blocked files, etc.)
├── scripts/
│   └── build.sh                 # builds Next.js to static, embeds in Go binary
├── go.mod
├── go.sum
└── Makefile
```

## Proxy Engine

Local HTTPS forward proxy built on `goproxy`.

### Startup Flow

1. Binary starts, picks a random free port for the proxy.
2. Auto-generates a local CA cert/key on first run, stores in `~/.redactr/certs/`.
3. `goproxy` starts with the CA, issues per-domain certs on the fly for MITM.
4. Proxy only intercepts requests to configured AI provider domains — all other traffic passes through untouched.
5. User trusts the CA cert on first run (guided by dashboard).

### Request Interception Flow

```
AI Tool -> HTTPS_PROXY=localhost:PORT -> Redactr Proxy
  -> Is destination an AI provider domain?
    -> No: forward untouched
    -> Yes: decrypt TLS -> extract request body -> send to scanning pipeline
      -> Pipeline returns redacted body -> re-encrypt -> forward to provider
```

### Response Interception

- Responses from providers are inspected for tool_use blocks containing dangerous file references (filename-based file blocking).
- Responses are scanned for any PII that might be echoed back.

### Proxy Off Behavior

1. Dashboard sends "disable" command via API.
2. Go proxy listener shuts down (port released).
3. Redactr unsets `HTTPS_PROXY` / `https_proxy` in the shell environment.
4. All MCP server configs are automatically unwrapped (restored to original).
5. Provider URL firewall rules are removed.
6. AI tools connect directly to their APIs.
7. Dashboard stays running — user can re-enable at any time.

### What the Proxy Does NOT Do

- No command execution interception — that is handled by Claude Code hooks.
- No full context scanning — only the last user message in the request payload.
- No scanning of non-AI-provider traffic.

### Domain Filtering

- Configurable allowlist/blocklist of domains the proxy intercepts.
- Default: intercept `api.anthropic.com`, `api.openai.com`, `api.githubcopilot.com` and related subdomains.
- Dashboard can add/remove domains at runtime.
- Blocked domains get connection refused.

### MCP Interception (Two Layers)

1. **Outbound traffic** — MCP servers' external API calls are routed through Redactr's proxy (set `HTTPS_PROXY` for MCP server subprocesses). Scanned like any other AI provider traffic.
2. **Local stdin/stdout wrapping** — `redactr-mcp-wrap` binary sits between the AI tool and the MCP server. The AI tool's MCP config points to `redactr-mcp-wrap <actual-mcp-command>`. The wrapper intercepts JSON-RPC messages on stdin/stdout, runs them through the scanning pipeline, and redacts before passing through.

**Integration with main process:**
- Wrapper connects to the running Redactr instance over localhost (discovers port from `~/.redactr/state`).
- Sends scan requests to the main pipeline — same regex, entropy, GLiNER, same cache.
- Logs appear in the dashboard alongside proxy logs, tagged as `source: mcp` with the MCP server name.
- If Redactr is not running or proxy is off, wrapper passes through transparently.

**Dashboard MCP management:**
- Lists all detected MCP servers from AI tool configs (auto-discovers from Claude Code, Copilot, Codex config files).
- One-click "Wrap with Redactr" / "Unwrap" buttons per MCP server.
- Shows which servers are currently wrapped and their live status.
- When proxy is turned off, all MCP configs are automatically unwrapped.

### Provider URL Blocking

When Redactr proxy is active, direct connections to AI providers that bypass the proxy are blocked at the OS firewall level.

**Platform support:**
- macOS: `pf` (packet filter) rules
- Linux: `iptables` rules
- Windows: `netsh advfirewall` rules

**Behavior:**
- Rules block outbound TCP to AI provider IPs except through Redactr's proxy port.
- Only blocks specific AI provider destinations, not general internet access.
- Rules added when proxy enables, removed when proxy disables.
- Dashboard shows active firewall rules and their status.

**Safety:**
- If Redactr crashes or is force-killed, a cleanup script removes stale rules on next start.
- `redactr cleanup` CLI command for manual emergency removal.
- Requires elevated permissions (sudo/Administrator) — prompted during first-run setup.

## Scanning Pipeline

Sequential four-layer pipeline that processes message content. All layers always run in order.

```
Input text (last user message)
  |
  +-- Cache Check: hash input, return cached result if hit
  |
  +-- Layer 1: Regex Scanner (~<1ms)
  |     Built-in patterns: emails, phone numbers, SSNs, credit cards,
  |     AWS keys, GCP keys, private keys, JWTs, connection strings
  |     Custom user-defined patterns from dashboard config
  |     Output: list of matches with pattern name + position
  |
  +-- Layer 2: Entropy Scanner (~<1ms)
  |     Shannon entropy on sliding token windows
  |     High entropy strings flagged as potential secrets/keys
  |     Configurable threshold from dashboard
  |     Output: list of high-entropy spans with entropy score
  |
  +-- Layer 3: GLiNER Model (~5-20ms on pre-redacted text)
  |     Runs on text AFTER L1+L2 redactions applied
  |     If regex already caught everything, GLiNER confirms quickly
  |     Catches contextual PII: names, addresses, medical terms
  |     Lazy-loaded ~60s after startup; L1+L2 only until then
  |     Local Python sidecar, GLiNER model loaded in memory
  |     Sidecar exposes HTTP endpoint on localhost (random port, registered in ~/.redactr/state/sidecar.port)
  |     If sidecar not ready, fall back to L1+L2 results (log warning)
  |     Output: list of entities with type + position + confidence
  |
  +-- Layer 4: Context Gate (future stub)
  |     Plain text business rules evaluated by a model
  |     Not implemented in v1, interface defined for extension
  |
  +-- Redactor merges all layer outputs
        Deduplicates overlapping detections (longest match wins)
        Applies dynamic labels: [REDACTED-EMAIL], [REDACTED-AWS-KEY],
        [REDACTED-ENTROPY-SECRET], [REDACTED-PERSON], [REDACTED-<custom-rule-name>]
        Returns redacted text + scan report (for logging/dashboard)
        Result cached for future requests
```

### File Blocking (Pre-check)

Runs before the scanning pipeline:
- **Filename check:** inspect tool_use payloads for blocked extensions (`.env`, `.tfstate`, `.pem`, `.key`, `.p12`, `.pfx`).
- **Content pattern check:** detect file content signatures (e.g., `KEY=value` blocks, JSON with credential-shaped fields).
- Blocked files fully replaced with `[REDACTED-FILE-<extension>: <filename>]`.
- Configurable from dashboard — add/remove blocked extensions and content patterns.

### What Gets Scanned

- Only the last user message in outgoing API requests (not full conversation context).
- MCP stdin/stdout JSON-RPC message payloads.
- Tool call results containing file contents.

### Caching

- In-memory LRU cache sits before the pipeline.
- Cache key: hash of the input text segment.
- Cache hit: return cached redacted text + scan report instantly.
- Cache miss: run full pipeline, store result.
- Bounded size, configurable from dashboard.
- Invalidated on config changes (regex patterns, custom rules, blocked file list).
- Cache stats exposed to dashboard (hit rate, size, evictions).

### Scan Report (per request, stored in BoltDB)

- Timestamp, target provider, latency.
- Which layers ran, what each found.
- Final redactions applied with dynamic labels.
- Pass/block decision and reason.

## Dashboard

Next.js app built to static assets, embedded in the Go binary via `embed` package. Served on a random free port alongside the REST/WebSocket API.

### Landing Page

- Big toggle: Redactr ON / OFF.
- Status indicators: proxy port, proxy uptime, GLiNER sidecar status (loading / ready / error).
- Quick stats: requests scanned today, redactions applied, cache hit rate, avg latency.

### Log View

- Real-time log stream via WebSocket.
- Each entry: timestamp, target provider (Claude/Copilot/Codex), latency, redaction count.
- Expandable detail: original vs redacted diff, which layers caught what, dynamic labels applied.
- Filterable by: provider, time range, redaction type, blocked vs passed.
- Blocked requests highlighted with explanation.

### Configuration Page

- **Scanning:** enable/disable individual layers, entropy threshold slider.
- **Regex patterns:** view built-in, add/edit/delete custom patterns with test input field.
- **Custom words:** blocklist of specific words/phrases to always redact.
- **File blocking:** manage blocked extensions and content patterns.
- **Domain restrictions:** allowlist/blocklist, add/remove at runtime.
- **Cache settings:** max cache size, view stats, manual clear button.
- **GLiNER sidecar:** status, restart button, model info.

### MCP Management Page

- Auto-discovers MCP servers from AI tool configs.
- One-click wrap/unwrap per MCP server.
- Live status of wrapped servers.

### Hooks Page

- Manage Claude Code hook configurations.
- View safecmd allowlist, add/remove overrides.
- Independent toggle from proxy.

### Latency Observability

- Per-request latency breakdown: proxy overhead, each scanner layer, total.
- Rolling latency chart (last hour / day).
- P50, P95, P99 latency stats.
- Cache hit rate over time.

### API

- REST for config CRUD and log queries.
- WebSocket for real-time log streaming and status updates.
- All on the same port as the dashboard (Go muxes API routes alongside static assets).

## Command Safety (Hooks)

Command safety is handled outside the proxy via Claude Code's native hook system.

- Redactr integrates **AnswerDotAI/safecmd** allowlist as the source of truth for safe commands.
- Redactr configures Claude Code hooks automatically from the dashboard (writes to `.claude/settings.json`).
- Hook validates commands against safecmd's allowlist before execution — AST-level parsing catches dangerous commands nested in pipes/subshells.
- Dashboard shows the full allowlist, lets users add/remove commands.
- For Copilot and Codex: future extension (not v1), interface designed to support other tool hook systems.
- Hooks toggle is independent from proxy toggle.
- All command attempts logged to BoltDB, visible in dashboard.

## Configuration & State Management

### Config File: `~/.redactr/config.yaml`

Single source of truth. Dashboard reads/writes via Go API. Changes take effect immediately (hot-reload).

```yaml
proxy:
  enabled: true
  intercepted_domains:
    - api.anthropic.com
    - api.openai.com
    - api.githubcopilot.com
  blocked_domains: []

scanning:
  regex_enabled: true
  entropy_enabled: true
  entropy_threshold: 4.5
  gliner_enabled: true
  custom_patterns: []
  custom_blocked_words: []
  cache_max_size: 10000

file_blocking:
  blocked_extensions: [".env", ".tfstate", ".pem", ".key", ".p12", ".pfx"]
  content_patterns_enabled: true

hooks:
  enabled: true
  claude_code: true
  safecmd_overrides:
    added: []
    removed: []

mcp:
  wrapped_servers: {}
```

### State Directory: `~/.redactr/`

```
~/.redactr/
├── config.yaml          # user config
├── certs/
│   ├── ca.crt           # generated root CA (user trusts this once)
│   └── ca.key           # CA private key
├── data/
│   └── logs.db          # BoltDB log storage
└── state/
    ├── proxy.pid         # current proxy PID + port
    ├── dashboard.port    # current dashboard port
    ├── api.port          # Go API port (MCP wrapper connects here)
    └── sidecar.port      # GLiNER sidecar port
```

### First-Run Flow

1. Binary starts, no `~/.redactr/` exists.
2. Creates directory, generates CA cert, writes default config.
3. Starts dashboard on random free port, opens browser.
4. Dashboard walks user through: trust the CA cert, configure AI tools' proxy settings.
5. User clicks "Enable Proxy" — proxy starts on random free port, env vars set, firewall rules added.

## Benchmarking Suite (Marketing Only)

Not production code. Validates and demonstrates detection capabilities.

### Synthetic Data Sources

- Gretel AI synthetic datasets (PII-rich generated data).
- Privy EU financial data.
- Custom generated test fixtures (emails, API keys, mixed code + PII).

### What Benchmarks Measure

- Detection accuracy per layer (regex, entropy, GLiNER) — precision, recall, F1.
- False positive rate (clean code incorrectly flagged).
- False negative rate (PII that slipped through).
- Latency per layer and end-to-end pipeline.
- Cache hit impact on throughput.

### Output

- Markdown reports with tables and stats.
- JSON results for programmatic consumption.

### Structure

```
benchmarks/
├── datasets/              # synthetic test data (gitignored, downloaded on demand)
├── runner.go              # benchmark harness
├── results/               # generated reports
└── README.md
```

Separate `make benchmark` target. Never runs in production. No impact on proxy binary size.

## Distribution

- **v1:** Single binary download. User downloads the Go binary, runs it, dashboard opens, guides setup.
- **Future:** Homebrew (`brew install redactr`), Docker container.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Proxy type | HTTPS forward proxy (goproxy) | Provider-agnostic, single config change per AI tool |
| Runtime | Go | Low latency proxy, single binary distribution |
| TLS interception | Auto-generated local CA | Pure Go, no mitmproxy Python dependency |
| PII model | GLiNER (local) | Fast inference, everything stays local |
| GLiNER hosting | Python sidecar, lazy-loaded | Avoids blocking proxy startup |
| Dashboard | Next.js embedded in Go binary | Single artifact, no separate deployment |
| Storage | BoltDB | Pure Go, embedded, no CGo, lightweight |
| Scanning strategy | Sequential all layers, with caching | Simple, predictable, cache eliminates redundant work |
| Redaction format | Dynamic `[REDACTED-<type>]` | LLM-friendly, extensible with custom rules |
| Command safety | Claude Code hooks + safecmd | Leverages native tool capabilities |
| Proxy off | Shut down + env var cleanup + firewall removal | Honest off state, no trust-me passthrough |
| Provider blocking | OS firewall (pf/iptables/netsh) | Prevents bypass while proxy is active |
| Context scanning | Last user message only | Keeps latency low |
| Context gate | Future stub | Designed for extension, not built in v1 |
