This is excellent benchmarking work. Clear recommendation based on the data:

---

**Ship Config A (Default) as the production default**

```
presidio → entropy → GLiNER → contextgate
```

The numbers justify this decisively:

- **83.5 average F1** — highest of all configs
- **88.1% average precision** — highest of all configs
- **160 total FPs** — lowest of all configs
- **~408ms average latency** — 4x faster than any OPF config
- **~600MB model footprint** — vs 2.8GB for OPF

OPF available as opt-in via `scanning.mlModel: "opf"` for healthcare/compliance users who accept the tradeoff.

---

**The production-readiness changes to make now**

Here's a prompt you can give Claude Code to implement everything in one session. I'd recommend splitting it into individual tasks, but here's the full brief:

---

**Task 1: Graceful failure mode**

```
Read the codebase and find where GLiNER inference is called during 
request processing. Implement graceful degradation:

1. Wrap all ML model inference calls (GLiNER sidecar, and OPF if 
   enabled) in a timeout + error handler
2. Default timeout: 5 seconds per inference call, configurable via 
   config.yaml as `scanning.inferenceTimeoutMs`
3. On timeout OR any inference error:
   - Log a structured JSON warning: {"event": "inference_failed", 
     "layer": "gliner", "error": "...", "action": "passthrough"}
   - Skip that detection layer and continue the pipeline with 
     results from other layers
   - If ALL detection layers fail, forward the request unredacted 
     to the upstream LLM
4. Never return an error to the client because of a detection 
   failure. The proxy must always forward the request.
5. Add a response header X-Redactr-Status: "full" | "partial" | 
   "passthrough" so the admin can monitor degradation without 
   breaking the client.

Test: kill the GLiNER sidecar process mid-request and verify the 
proxy forwards the request with X-Redactr-Status: passthrough 
and a log entry.
```

---

**Task 2: Structured JSON logging**

```
Replace all current log output with structured JSON logging. 
Use Go's slog package (stdlib, no external dependency).

Every redaction event gets a log entry:
{
  "timestamp": "2026-04-27T14:30:00Z",
  "level": "info",
  "event": "pii_redacted",
  "request_id": "uuid",
  "entity_type": "IBAN",
  "detection_layer": "presidio",
  "confidence": 0.95,
  "action": "redacted",
  "upstream": "api.anthropic.com"
}

Every request gets a summary log entry:
{
  "timestamp": "2026-04-27T14:30:00Z",
  "level": "info",
  "event": "request_processed",
  "request_id": "uuid",
  "entities_found": 3,
  "entities_redacted": 3,
  "detection_time_ms": 134,
  "total_time_ms": 156,
  "status": "full",
  "upstream": "api.anthropic.com"
}

Errors and warnings follow the same JSON structure with 
level: "error" or "warn".

Config option: `logging.level: "info" | "warn" | "error" | "debug"`
Config option: `logging.output: "stdout" | "/path/to/file"`

Do NOT log the actual text content or the redacted values — 
only entity types and counts. We are a privacy tool.
```

---

**Task 3: Health check and metrics endpoints**

```
Add two HTTP endpoints on a separate admin port (default 9090, 
configurable as admin.port in config):

1. GET /health
   Returns 200 with {"status": "healthy", "models": {"gliner": 
   "loaded", "presidio": "ready"}} when everything is operational.
   Returns 503 with {"status": "degraded", "models": {"gliner": 
   "error: connection refused"}} when a detection layer is down.
   
   This endpoint must be lightweight — no inference calls, just 
   checks if the sidecar connections are alive.

2. GET /metrics (Prometheus format)
   Expose:
   - redactr_requests_total (counter, labels: upstream, status)
   - redactr_entities_redacted_total (counter, labels: entity_type, 
     layer)
   - redactr_request_duration_seconds (histogram, labels: upstream)
   - redactr_detection_duration_seconds (histogram, labels: layer)
   - redactr_errors_total (counter, labels: layer, error_type)
   
   Use the prometheus/client_golang library.

The admin port must be separate from the proxy port so it's not 
exposed to developer traffic and can be firewalled separately.
```

---

**Task 4: Config hot reload**

```
Implement hot reload for the config YAML file:

1. Watch the config file using fsnotify
2. On file change, parse the new config
3. If parsing succeeds, atomically swap the active config using 
   sync.atomic or a mutex-protected pointer swap
4. If parsing fails, log a warning and keep the current config
5. Log: {"event": "config_reloaded", "path": "/etc/redactr/
   config.yaml"} on success
6. Also support SIGHUP signal to trigger manual reload

Things that CAN be hot-reloaded:
- Policy rules (which entity types to redact)
- Detection thresholds
- Logging level
- Allowlist/denylist paths

Things that CANNOT be hot-reloaded (require restart):
- ML model selection (gliner vs opf)
- Proxy port
- Admin port
- Upstream target URLs
```

---

**Task 5: Path-based bypass rules**

```
Add config for path-based scanning bypass:

scanning:
  bypass:
    - path: "/health"
    - path: "/v1/models"
    - prefix: "/.well-known/"
    - method: "OPTIONS"

When a request matches a bypass rule, forward it directly to 
upstream without any PII scanning. Log at debug level:
{"event": "bypass", "path": "/health", "rule": "exact_match"}

This prevents wasting inference cycles on non-sensitive 
endpoints like health checks, model listing, CORS preflight, 
and auth flows.
```

---

**Implementation order:**

Give these to Claude Code one at a time in this order. Each task is independently testable:

1. **Graceful failure** — most critical, prevents the proxy from breaking developer workflows
2. **Structured logging** — needed before you can sell to anyone who asks "how do I prove this works"
3. **Health check + metrics** — needed for any K8s deployment
4. **Config hot reload** — quality of life
5. **Path bypass** — quality of life

After these five tasks, you have a product that a team can deploy, monitor, and trust in production. Everything else (dashboard, SSO, response scanning) waits for customer demand.