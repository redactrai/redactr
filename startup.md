# Redactr — Startup Guide

> This guide covers the **standalone client daemon** only. For team mode (the
> `redactr-server` control plane, device enrollment, and sandboxed agent front
> doors like `redactr claude` / `redactr code`), see the **Components** and
> **Quick Start — team mode** sections of [README.md](README.md).

## Quick Start

```bash
go run ./cmd/redactr
```

This starts the full stack:

| Component | Default Address | Purpose |
|-----------|----------------|---------|
| MITM Proxy | random port (printed at startup) | Intercepts and redacts PII from LLM API calls |
| Dashboard | `:9080` | Web UI for config, logs, and live scanning |
| Admin/Metrics | `:9090` | `/health` and `/metrics` (Prometheus) |
| GLiNER Sidecar | random port | ML-based PII detection (Python process) |

## Prerequisites

### Go binary (required)

```bash
go build -o redactr ./cmd/redactr
```

### GLiNER sidecar (optional)

The GLiNER ML model runs as a Python sidecar. Without it, the proxy still works using Presidio (regex) + entropy detection.

```bash
cd sidecar/gliner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If the sidecar isn't running, GLiNER is skipped gracefully — the proxy continues with the remaining detection layers.

To disable GLiNER entirely, edit `~/.redactr/config.yaml`:

```yaml
scanning:
  gliner_enabled: false
```

## Trust the CA Certificate

The proxy performs MITM TLS interception. Your HTTP client must trust the generated CA certificate.

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.redactr/certs/ca.crt
```

### Linux

```bash
sudo cp ~/.redactr/certs/ca.crt /usr/local/share/ca-certificates/redactr.crt
sudo update-ca-certificates
```

### Windows

```powershell
Import-Certificate -FilePath "$env:USERPROFILE\.redactr\certs\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

## Route Traffic Through the Proxy

Set the proxy address printed at startup (e.g. `127.0.0.1:54321`):

```bash
export HTTPS_PROXY=http://127.0.0.1:<port>
export HTTP_PROXY=http://127.0.0.1:<port>
```

Or configure per-tool:

```bash
# Claude Code
HTTPS_PROXY=http://127.0.0.1:<port> claude

# curl
curl --proxy http://127.0.0.1:<port> https://api.anthropic.com/v1/messages ...
```

## Configuration

Config lives at `~/.redactr/config.yaml`. It is created with defaults on first run.

Key settings:

```yaml
proxy:
  enabled: true                    # start proxy on launch
  intercepted_domains:             # domains to MITM
    - api.anthropic.com
    - api.openai.com
    - api.githubcopilot.com

scanning:
  inference_timeout_ms: 5000       # per-layer timeout
  entropy_threshold: 4.5           # entropy scanner sensitivity
  bypass:                          # skip scanning for these paths
    - path: "/v1/models"
    - prefix: "/.well-known/"
    - method: "OPTIONS"

admin:
  port: 9090                       # health + metrics port

logging:
  level: info                      # debug | info | warn | error
  output: stdout                   # stdout | stderr | /path/to/file

licensing:
  key: ""                          # empty = demo license (all features)
```

Config supports hot reload — edit the file while running and changes take effect immediately (rules, thresholds, log level, bypass rules). Proxy port and ML model selection require a restart.

SIGHUP also triggers a reload:

```bash
kill -HUP $(pgrep redactr)
```

## Picking up code changes

Just re-run:

```bash
go run ./cmd/redactr
```

A live predecessor (compiled binary, `go run` parent, anything holding the singleton lock at `~/.redactr/state/redactr.pid`) is detected, sent `SIGTERM`, given a 5s grace, then `SIGKILL`'d if needed. The new instance also reaps any orphaned GLiNER sidecar and stale pf rules from a prior crash, so a forceful kill (`kill -9`) is also recovered automatically on the next start.

If a non-redactr process happens to hold the pidfile PID (PID reuse), startup refuses with a clear error rather than killing a stranger — investigate and remove `~/.redactr/state/redactr.pid` manually.

## Endpoints

### Dashboard (`:9080`)

- `GET /` — Web UI
- `POST /api/scan` — Test scan: `{"text": "my email is user@example.com"}`
- `GET /api/logs` — Recent scan reports
- `GET /api/stats` — 24h statistics
- `GET /api/license` — License status
- `GET /api/rules` — Detection rule configuration

### Admin (`:9090`)

- `GET /health` — Returns 200 if all layers ready, 503 if degraded
- `GET /metrics` — Prometheus metrics

## Subcommands

```bash
# Start the daemon: proxy + dashboard (:9080) + admin/metrics (:9090) (default)
redactr

# Interactive shell with proxy + CA env pre-configured (host-bound, no container)
redactr shell

# Launch an AI agent inside a hardened container, egress force-routed to the proxy
# (requires a container runtime — Docker/Podman/Colima — and, for the policy image,
#  enrollment with a control plane; see README team mode)
redactr claude [args]
redactr codex [args]
redactr copilot [args]

# Generate/open a VS Code Dev Container for a project (the Copilot gate)
redactr code <project> [--force]

# Enroll this device with a control-plane server
redactr enroll --server <url> --token <enrollment-token>

# System-tray client with a green/red proxy on/off indicator
redactr tray

# Clean up firewall rules left from a crash
redactr cleanup
```

> The container/enrollment subcommands (`claude`, `code`, `enroll`, `tray`) are
> the v2 team-mode surface — see [README.md](README.md). `redactr`, `shell`, and
> `cleanup` are the standalone-daemon commands this guide focuses on.

## Troubleshooting

**Proxy starts but no traffic is intercepted**
- Check `HTTPS_PROXY` is set to the printed address
- Verify the domain is in `intercepted_domains`

**Certificate errors**
- Trust the CA cert (see above)
- Regenerate: delete `~/.redactr/certs/` and restart

**GLiNER not loading**
- Check Python venv is set up in `sidecar/gliner/`
- The sidecar takes 8-9 seconds to load the model on first start
- Watch logs for `sidecar_ready` or `sidecar_timeout` events

**Dashboard not loading**
- Default port is 9080 — check nothing else is using it
- Try `http://localhost:9080`
