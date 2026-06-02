# Transparent Proxy Routing — Design

**Status:** Approved for implementation planning
**Author:** Redactr team (brainstormed 2026-04-30)
**Scope:** Make "Enable Proxy" in the dashboard actually route AI-tool traffic through Redactr automatically, instead of silently starting a listener that nothing routes to.

---

## 1. Problem

Today's "Enable Proxy" toggle starts a listener on a local port (e.g. `:58600`) and updates `cfg.Proxy.Enabled = true`. It does **nothing** to route traffic. As a result the dashboard shows a green "Proxy active" indicator while every AI tool on the machine bypasses Redactr entirely.

The user-visible failure: blatant PII (emails, AWS keys, SSNs) flows directly to Anthropic, OpenAI, etc., even though the dashboard claims interception is happening. Confirmed during this brainstorm: the running daemon's `/api/scan` endpoint redacts cleanly, but `/api/sessions` shows multiple `runaway` Claude processes with direct TCP connections to AI providers.

---

## 2. Goals & non-goals

**Goals**
- Clicking **Enable Proxy** in the dashboard installs OS-level traffic redirection so any new TCP connection from any process to a configured AI provider lands on the local Redactr proxy.
- Clicking **Disable Proxy** removes those rules.
- The Redactr CA cert is installed into the system trust store automatically on first enable (so MITM doesn't trip TLS errors in clients).
- Existing AI-tool processes whose TCP connections were already established are clearly surfaced in the dashboard as `runaway` (already implemented).
- All elevated operations happen via a single `osascript "do shell script ... with administrator privileges"` invocation per Enable/Disable click — one macOS GUI password prompt for the whole batch.
- DNS for AI hosts is re-resolved every 5 minutes; pf rules are reconciled to track IP changes.
- macOS-first. Linux and Windows return a clear "not implemented" status from the same `firewall.Manager` interface; dashboard surfaces this so the user sees why traffic isn't being routed on those platforms.

**Non-goals (deferred)**
- Linux iptables / Windows WFP implementations (interface is clean enough for someone to add later).
- Domain-level / DNS-level interception (rejected during brainstorm — Chromium-based clients use DoH and bypass system DNS).
- CIDR-range scraping for AI providers (the 5-minute DNS resolver loop is sufficient for v1).
- A "system-wide proxy" mode that routes ALL TLS traffic through Redactr (rejected — too broad).
- Existing-process re-routing (kernel can't re-establish their TCP connections; the dashboard's *Sessions → Stop & reopen protected* flow handles this).
- Custom CA install on Linux/Windows trust stores.

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  redactr daemon (user-mode)                                       │
│                                                                   │
│  ┌─────────────────┐    ┌────────────────────┐    ┌────────────┐  │
│  │ Dashboard       │    │ DNS resolver loop  │    │ Proxy      │  │
│  │ POST /api/proxy │    │ tick = 5 min       │───▶│ goproxy    │  │
│  │   /enable       │    │ resolves AI hosts  │    │ (existing) │  │
│  │   /disable      │    │ → desired IP set   │    │ port 58600 │  │
│  └────────┬────────┘    └─────────┬──────────┘    └────▲───────┘  │
│           │                       │                    │          │
│           ▼                       ▼                    │          │
│  ┌─────────────────────────────────────────────┐       │          │
│  │ FirewallController                          │       │          │
│  │ - reconciles desired vs current pf rule set │       │          │
│  │ - emits one osascript invocation per change │       │          │
│  │ - tracks last-installed IPs to avoid churn  │       │          │
│  └─────────────────┬───────────────────────────┘       │          │
│                    │                                   │          │
│  ┌─────────────────▼───────────────────────────┐       │          │
│  │ Transparent listener (NEW)                  │       │          │
│  │ OS-assigned port (bind :0, then used        │       │          │
│  │ in the pf rdr rules)                        │       │          │
│  │ - accept TCP                                │       │          │
│  │ - read TLS ClientHello, extract SNI         │       │          │
│  │ - look up original dest from pf state OR    │       │          │
│  │   trust SNI as the hostname                 │       │          │
│  │ - splice into goproxy MITM path             │       │          │
│  └─────────────────────────────────────────────┘       │          │
│                                                                   │
└──────────────────┬────────────────────────────────────────────────┘
                   │ osascript -e 'do shell script ".../redactr-firewall apply ..." with administrator privileges'
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  redactr-firewall helper script (sudo'd, one shot per click)     │
│                                                                  │
│  apply <proxy-port> <ip,ip,ip>:                                  │
│    - install Redactr CA into /Library/Keychains/System.keychain  │
│      (idempotent: skip if fingerprint already trusted)           │
│    - pfctl -a com.redactr -F all                                 │
│    - generate rdr rules from <ip> list:                          │
│        rdr pass on lo0 inet proto tcp from any to <ip> port 443  │
│            -> 127.0.0.1 port <transparent-port>                  │
│    - pfctl -a com.redactr -f -                                   │
│    - pfctl -E   (enable pf if not already)                       │
│                                                                  │
│  remove:                                                         │
│    - pfctl -a com.redactr -F all                                 │
│    (CA stays installed; user can remove via Keychain Access)     │
│                                                                  │
│  status:                                                         │
│    - prints pfctl -a com.redactr -sr output                      │
└──────────────────────────────────────────────────────────────────┘
```

### Key flow on Enable

1. `POST /api/proxy/enable` → start the existing goproxy listener AND the new transparent listener (both bind on `:0`; OS assigns ports). Capture the transparent-listener's actual port for use in pf rules.
2. Resolve every host in `cfg.Proxy.InterceptedDomains` to a set of IPs.
3. Run the `redactr-firewall` helper script via `osascript`. macOS pops the GUI password dialog **once**.
4. The script installs the CA cert (idempotent) and writes the pf rules into the `com.redactr` anchor.
5. Daemon writes `proxy.pid` state file with `<port>:<transparent-port>:<pid>` so `redactr cleanup` can recover.
6. DNS resolver loop runs every 5 minutes; if the resolved set changes, it re-runs the helper to install the diff.

### Key flow on Disable

1. `POST /api/proxy/disable` → run the helper with `remove`. macOS prompts for password again unless cached (~5 min).
2. Stop both listeners.
3. Clear `proxy.pid`.

---

## 4. Components

### New files
- `internal/firewall/redirect_darwin.go` — implementation of `Redirect(domains []string, transparentPort int) error` and `Unredirect() error` using pf rdr rules. Replaces the no-op default in `darwin.go`'s `BlockDirect`.
- `internal/firewall/script_darwin.go` — generates the shell script that gets passed to osascript. One function: `BuildApplyScript(caPath, anchor string, ips []string, transparentPort int) string`. Pure string builder, easy to test.
- `internal/proxy/transparent.go` — the SNI-sniffing transparent listener. Reads TLS ClientHello, extracts SNI, hands off to a goproxy-compatible session.
- `internal/firewall/dns_loop.go` — the resolver loop. Single goroutine, ticker-driven, exposes a channel that the FirewallController watches.
- `cmd/redactr/firewall_cmd.go` — handlers for new subcommands `redactr firewall apply <args>`, `redactr firewall remove`, `redactr firewall status` (these are the privileged operations, run by the elevated osascript shell).

### Modified files
- `internal/firewall/firewall.go` — extend `Manager` interface with:
  - `Redirect(domains []string, transparentPort int) error`
  - `Unredirect() error`
  - `IsActive() bool`
- `internal/firewall/linux.go`, `windows.go` — stub the new methods, returning `errPlatformNotSupported`.
- `internal/api/routes.go` (`handleProxyEnable`, `handleProxyDisable`) — call FirewallController after starting/stopping listeners.
- `internal/proxy/proxy.go` — extend with a `StartTransparent(port int) (string, error)` method that runs the new transparent listener.
- `cmd/redactr/main.go` — wire up the FirewallController and DNS loop. Pass them to the API server.
- `internal/api/server.go` — accept the FirewallController as a dependency.

### Why the helper script lives inline (not as a separate file)

The macOS `osascript` command can take multi-line shell scripts as a string. We don't need to ship a separate `redactr-firewall.sh` and worry about install paths or signing. The daemon constructs the script in Go and passes it to `osascript -e` as a single string argument. Self-contained, version-locked, no installer.

---

## 5. Privilege model

- The daemon runs as the user (current behaviour, unchanged).
- Privileged ops happen in a one-shot subprocess: `osascript -e 'do shell script "…" with administrator privileges'`.
- macOS shows the standard system password dialog. After unlock, sudo is cached for ~5 minutes; subsequent invocations within that window don't prompt.
- The DNS resolver loop's reconcile diffs are typically small enough to fit inside that window. If the user toggles disable then immediately re-enable, no re-prompt.
- We do NOT install a setuid helper, do NOT modify the user's sudoers file, do NOT ship a privileged daemon. Each elevation is bounded, audit-logged by macOS, and revocable by cancelling the dialog.

---

## 6. Transparent listener — how SNI parsing works

When pf rewrites the destination, the original IP/hostname is lost from the kernel-level connection metadata available to the proxy. macOS does NOT expose `SO_ORIGINAL_DST` like Linux does. So we extract the hostname from the TLS handshake itself:

1. New TCP connection arrives on the transparent port.
2. We read up to 4 KB of the first chunk (the TLS ClientHello).
3. Parse the ClientHello to extract the `server_name` extension (SNI). The Go stdlib has helpers in `crypto/tls`, but for read-only parsing we use a small ad-hoc parser to avoid consuming the bytes (we need to forward them onward).
4. If SNI is present and matches a configured intercepted domain → splice the connection into goproxy as if a `CONNECT <hostname>:443` had arrived. Goproxy's MITM machinery generates a leaf cert for that hostname (signed by the Redactr CA, which is now trusted), terminates the TLS, decodes the request, runs it through the scanner pipeline, and re-encrypts to the upstream.
5. If SNI is missing or doesn't match → log and close the connection. (We could transparently bridge to the original destination, but determining the destination without `SO_ORIGINAL_DST` is fragile; safer to fail loud.) Edge case: requesting a non-AI host whose IP happens to coincide with an AI provider's IP (Anycast collision). Acceptable false-rejection rate at v1.

The SNI parser is a focused unit (~100 lines, fully unit-testable with golden TLS hello bytes).

---

## 7. CA trust handling

On first Enable Proxy, the helper script runs:

```sh
if ! security find-certificate -c "Redactr Root CA" /Library/Keychains/System.keychain &>/dev/null; then
  security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    "<caPath>"
fi
```

- Idempotent — re-running is a no-op.
- The user can revoke trust at any time via Keychain Access.
- We do NOT remove the CA on Disable. Reasoning: re-enabling shouldn't re-prompt, and a "leftover" trusted CA is no worse than a trusted CA that's actively being used. If the user wants full removal they can run `security delete-certificate` themselves or use Keychain Access.

The Redactr CA file already exists at `~/.redactr/certs/ca.crt` (created on first daemon start). The helper script reads it as the first script argument.

---

## 8. Failure modes & UX

| Scenario | Behaviour |
|---|---|
| User cancels sudo prompt | osascript returns non-zero. Daemon catches, logs, returns 500 from `POST /api/proxy/enable`. Listener stays up but pf rules NOT installed. Dashboard shows the proxy as **listening-not-routed** (new tri-state) with a Retry button and a hint: *"Routing requires admin privileges."* |
| pfctl fails (e.g. pf disabled by user, conflict with another tool) | Helper script exits with error, stderr is captured. Daemon shows "Routing failed: <error>" in dashboard. Listener still up; user can remediate manually. |
| DNS lookup fails for one host | Log a warning, keep existing rules for that host. Don't tear down everything. |
| Helper exits but rules already installed | Idempotent on next click — rules are flushed and re-applied. |
| User deletes the Redactr CA from keychain | Next AI-tool request will trip TLS error. Visible in scan logs as `tls: certificate verify failed`. Re-enable proxy reinstalls. |
| Daemon crash with rules installed | `proxy.pid` state file lets `redactr cleanup` find the anchor and flush. macOS reboot also clears pf state. |
| Linux / Windows | `Redirect` returns `errors.New("transparent routing not yet implemented on <os>")`. Dashboard banner reads: *"Routing setup is macOS-only in this version. Set HTTPS_PROXY manually or use `redactr shell` for now."* |

### Dashboard surface

The proxy pill in the topbar gets a **third visual state**:

- `OFFLINE` (red dot, current) — listener not running.
- `LISTENING` (yellow dot, NEW) — listener running, but pf rules not installed (cancelled sudo, helper failed, or non-macOS platform).
- `ACTIVE` (green dot with pulse, current "on" state) — listener running AND firewall rules verified present.

A small chevron expanded the pill shows: addr, transparent-listener addr, # of pf rules, last DNS reconcile time. Same surface used today for the Sessions tab can be reused.

---

## 9. State persistence

`~/.redactr/state/firewall.json` holds:
```json
{
  "active": true,
  "proxy_addr": "127.0.0.1:58600",
  "transparent_addr": "127.0.0.1:58601",   // example; OS-assigned at bind time
  "ips": ["160.79.104.10", "104.18.39.123", ...],
  "last_reconciled": "2026-04-30T16:42:11Z",
  "ca_installed": true
}
```

Used by `redactr cleanup` to know what to flush. Updated atomically on every reconcile.

---

## 10. Testing

- **Unit: SNI parser.** Golden ClientHello bytes for `api.anthropic.com`, `api.openai.com`, malformed hello, no-SNI hello, oversized record. Assert hostname extraction or controlled rejection.
- **Unit: helper script generator.** Verify the generated shell script is syntactically valid (parse with `bash -n` in test) and contains the expected pf rules and CA-install branch.
- **Unit: DNS resolver loop.** Mock the resolver, assert reconcile detects added/removed IPs.
- **Unit: FirewallController.** Mock the `osascript` invocation, assert it's called with the right script and not called when the desired and current sets match.
- **Integration: macOS only.** A test harness that:
  1. Starts a fake AI server on a random IP (binds to `lo0` alias `127.0.0.99`).
  2. Adds `127.0.0.99` to the intercepted-IP set.
  3. Issues a `GET https://127.0.0.99/` from the test process.
  4. Verifies the request was MITM'd and a scan log entry was created.
  Run only when `RUN_FIREWALL_TESTS=1` is set, since it requires sudo.
- **Manual smoke checklist:** included in PR description. Open dashboard, click Enable Proxy, password prompt appears, enter password. From a fresh terminal: `curl -v https://api.anthropic.com/`. Verify scan-log entry appears. Click Disable Proxy. Same curl now connects directly.

---

## 11. Migration & cleanup behaviour

- Pre-existing config: no migration. The `cfg.Proxy.Enabled` semantics change from "listener up" to "listener up + routing installed", but the on-disk YAML key is unchanged.
- `redactr cleanup` (existing subcommand) gets a small upgrade: read `firewall.json`, flush the pf anchor, remove the state file.
- On graceful daemon shutdown: also flush the anchor. Don't leave the user surprised by TLS failures after redactr exits.

---

## 12. Open questions

None at design-approval time.

---

## 13. Out of scope (explicitly)

- Linux iptables / Windows WFP implementations.
- Domain-level interception via DoH-aware resolver (rejected — Chromium clients bypass).
- Auto-enabling pf if disabled at the OS level (we surface the error, don't silently `pfctl -E`).
- Splitting the helper into a setuid binary (per-toggle GUI prompt is acceptable for v1).
- Auto-trust-root removal on disable.
