# Fixed proxy port + friendly errors + bound-shell indicator

## Problem

`redactr shell` exports `HTTPS_PROXY=http://127.0.0.1:<random>`. The port is OS-assigned at proxy start, so:

1. After redactr restarts on a different port, every shell launched by the *previous* `redactr shell` invocation still points at the old (now dead) address. brew, curl, Claude Code, etc., fail with `connection refused` to a localhost port that means nothing to the user.
2. When the proxy is disabled (toggled off in the dashboard), the listener is fully closed, so the failure is the same `connection refused` — no signal that "redactr is *intentionally* off, go enable it."
3. Nothing in the bound shell tells the user they're inside a redactr-bound subshell, so the failure mode is invisible until something fails.

## Design

### 1. Fixed port

- New config field `proxy.port` (default `47474`).
- `proxy.Start(port)` is called with `cfg.Proxy.Port` instead of `0`.
- If the port is occupied at startup, fail with a clear error pointing at the conflicting process: `proxy port 47474 is already in use (try 'lsof -iTCP:47474')`. No silent fallback to a random port — predictability is the entire point.
- Configurable via `~/.redactr/config.yaml`:
  ```yaml
  proxy:
    port: 47474
  ```
- Port change requires a restart (consistent with existing `startup.md` note about proxy port).

`47474` was picked from IANA's dynamic range (49152–65535 is reserved for ephemeral allocation, but most user-process picks land below 50000 and 47474 is below the boundary while still high enough to avoid common dev tools). It has no known collisions in `nmap-services` or major dev-tooling docs, and the `4-7-4-7-4` pattern makes it memorable.

### 2. Listener always on + friendly 502

Today the proxy listener's lifetime equals the "proxy enabled" state — toggling off closes the listener. The new model decouples the two:

| Daemon state | "Scan" flag | Listener bound? | Behavior |
|---|---|---|---|
| Down | n/a | No | Kernel RST (unavoidable; covered by prompt indicator below) |
| Up | Off | Yes | All requests answered with `HTTP 502` and a fixed body |
| Up | On | Yes | MITM + scan + forward (today's behavior) |

**Implementation:**

- `Proxy` struct gains an atomic `scanEnabled bool`. Setter `Proxy.SetScanEnabled(bool)`. Reader from inside the goproxy handlers.
- A `goproxy.OnRequest()` hook runs first; if `scanEnabled` is false it returns:
  ```
  HTTP/1.1 502 Bad Gateway
  Content-Type: text/plain; charset=utf-8

  redactr proxy is currently disabled.
  Enable it from the dashboard at http://127.0.0.1:9080.
  ```
- For `CONNECT` requests (the HTTPS path that brew/curl use), `goproxy.OnRequest().HandleConnectFunc` returns `goproxy.RejectConnect` with the same 502 body.
- `main.go` calls `p.Start(cfg.Proxy.Port)` unconditionally. `cfg.Proxy.Enabled` becomes the initial value of `scanEnabled` rather than the gate on whether to bind.
- Dashboard's existing enable/disable toggle calls `Proxy.SetScanEnabled` instead of starting/stopping the proxy.

This change does not affect the firewall controller — pf rdr rules are independent of the listener-state distinction. They continue to be installed/flushed by the dashboard's separate firewall toggle.

### 3. Bound-shell prompt indicator + liveness check

`redactr shell` is extended to write a temporary rc file that wraps the user's existing rc and adds a prompt prefix that reflects proxy liveness.

**Per-shell handling:**

- **zsh**: write `<tempdir>/.zshrc` and launch with `ZDOTDIR=<tempdir>`. The rc sources `~/.zshrc` if present, then defines a `precmd` function and sets `PROMPT="${redactr_prefix}${PROMPT}"`.
- **bash**: write `<tempdir>/redactr.bashrc` and launch with `bash --rcfile <tempdir>/redactr.bashrc -i`. The rc sources `~/.bashrc` then sets `PROMPT_COMMAND` and `PS1`.
- **other shells (fish, etc.)**: skip the rc trick, fall through to current behavior. (Documented limitation.)
- The temp directory is created under `os.TempDir()` and cleaned up on shell exit via a trap inside the rc file.

**Liveness probe:**

- A 200ms TCP dial to `127.0.0.1:$REDACTR_PROXY_PORT`.
- Cached for 5 seconds in a shell variable to avoid hammering on busy prompts.
- Result drives the prefix:
  - alive: `(redactr)` in dim cyan
  - dead: `(redactr OFFLINE)` in red

The probe is deliberately just a TCP dial — not an HTTP request. It costs ~5–50µs on localhost and tells us whether *something* is listening on the port. That's sufficient to distinguish "daemon dead" from "daemon up" — which is the only signal the prompt needs to convey. The 502-vs-200 distinction is left to the response body when the user actually issues a request.

### 4. Migration

After upgrade, any open `redactr shell` from a prior daemon still has the old random port baked in. Documented in `startup.md`:

> After upgrading to the fixed-port build, `exit` any open `redactr shell` and re-enter so the new shell picks up `HTTPS_PROXY=http://127.0.0.1:47474`.

No data migration. Config is migrated automatically: if `proxy.port` is missing from the user's config, the default `47474` is filled in by the existing config-load path (which already merges defaults).

## Failure modes

| Case | Behavior |
|---|---|
| Port 47474 already in use at startup | Fatal with explicit error pointing at `lsof -iTCP:47474` |
| User configures invalid port (0, >65535) | Config validation rejects at load time |
| Liveness probe times out (>200ms) | Treated as "dead" — prompt shows OFFLINE |
| User's shell is fish/csh/etc. | rc-file trick is skipped; banner-only behavior, same as today |
| User's `~/.zshrc` errors out | The rc wrapper logs but continues — bound shell still works |

## Testing

- **Unit (proxy)**: `Proxy.SetScanEnabled(false)` → mock request → expect 502 response with the documented body. `SetScanEnabled(true)` → expect normal forward.
- **Unit (config)**: default config has `proxy.port: 47474`. Loading config without the field still produces 47474. Loading config with port `0` or `99999` returns a validation error.
- **Integration**: spawn proxy on test port, send `CONNECT` with scan disabled, expect 502 status line.
- **Manual smoke**: `redactr shell` → check prompt shows `(redactr)`. Stop redactr daemon → next prompt should show `(redactr OFFLINE)` within ≤5s.
