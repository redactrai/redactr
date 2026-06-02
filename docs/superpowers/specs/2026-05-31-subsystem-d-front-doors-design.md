# Redactr v2 — Subsystem D: Front Doors Design

**Status:** Design (autonomous-build mandate). Implementation plan follows. **Final v2 subsystem.**
**Date:** 2026-05-31
**Parent:** architecture spec (subsystem D). C (sandbox), B (daemon/CLI), A (control plane) merged.
**Fills SEAMs:** the sandbox `ModeStdioAttached` SEAM; the architecture's "VS Code Dev Container" and "MCP-wrap → container" front doors.

## The three front doors (recap)

The architecture unified protection around **execution hosts**, served by three front doors over one container model:

| Front door | Command | Status |
|---|---|---|
| CLI agents | `redactr claude/codex/copilot` | **built** (C + B) |
| Editor plugins | `redactr code <project>` → Dev Container | **this subsystem** (the Copilot gate) |
| Desktop MCP | `redactr-mcp-wrap` → MCP server in container | **this subsystem** |

## Reality check (testable vs deferred)

Real execution needs Docker (containers) and VS Code / the `devcontainer` CLI — not available here. Per the established pattern (C's container runs), this subsystem builds the **Go orchestration** — `devcontainer.json` generation, the stdio-attached container argv, the CLI preflight + file writing + command invocation behind a runner seam — fully unit-tested; the **actual `devcontainer up` / VS Code attach / container run is deferred** and documented.

## Components

### D1 — `redactr code <project>` (Dev Container; the Copilot gate)
Sandboxes *every* VS Code-family AI plugin at once by running the workspace's extension host inside a redactr container.
- **`internal/devcontainer`**: `Generate(in GenerateInput) ([]byte, error)` → a `.devcontainer/devcontainer.json` that pins `image` to the policy image, sets `containerEnv` (`HTTPS_PROXY`/`HTTP_PROXY`/CA vars/`REDACTR_BOUND`) pointing at `host.docker.internal:<proxyPort>`, mounts the CA read-only, and adds `runArgs` for the hardening profile + `--add-host host.docker.internal:host-gateway`. (Reuses the same injection facts as `sandbox.InjectionArgs`, expressed in devcontainer schema.)
- **`redactr code <project>` CLI**: preflight identical to `RunAgent` (EnsureDaemon → EnableProxy → LaunchPolicy) → write `<project>/.devcontainer/devcontainer.json` (don't clobber an existing one without `--force`) → invoke `devcontainer up --workspace-folder <project>` via a **runner seam** if the `devcontainer` CLI is present, else print the exact "Reopen in Container" instructions. Native host VS Code (no container) stays the redact-via-pf + flag path (carrot posture) — unchanged here.

### D2 — `redactr-mcp-wrap` → container (Desktop MCP sandboxing)
Today `redactr-mcp-wrap <cmd>` runs the MCP server as a **host child** and JSON-RPC-MITMs stdin/stdout (redaction). D2 lets it run the MCP server **inside a redactr container** while keeping the identical MITM loop.
- **Sandbox stdio-attached argv**: implement the `ModeStdioAttached` SEAM as `sandbox.StdioRunArgs(spec) ([]string, error)` — composes `<runtime> run --rm -i` (note `-i`, no tty) + hardening + injection + image + entrypoint. (No new runner: the caller execs this argv as a child and pipes stdio, exactly as `redactr-mcp-wrap` already does for the host child.)
- **`redactr-mcp-wrap --container [--image <ref>] <cmd>`**: when `--container` is set, build a `sandbox.Spec` (mount the cwd, inject proxy/CA from daemon state, entrypoint = `<cmd>`), get `StdioRunArgs`, and run THAT as the child (instead of `<cmd>` directly) — the existing `mcpwrap.ScanMessage` stdin/stdout redaction MITM is unchanged. Without `--container`, behavior is exactly as today (host child) — fully backward-compatible.

## Data flow

```
redactr code <proj>:  preflight → write .devcontainer/devcontainer.json (image+proxy env+CA+hardening)
                      → devcontainer up  (VS Code extension host runs IN the container → agents sandboxed + proxy-routed)
redactr-mcp-wrap --container <cmd>:  StdioRunArgs(spec) → exec `docker run --rm -i <image> <cmd>`
                      editor ⇄ [ScanMessage redaction MITM] ⇄ containerized MCP server (stdio)
```

## Error handling

| Case | Behavior |
|---|---|
| `.devcontainer/devcontainer.json` exists | refuse without `--force`; with `--force`, overwrite |
| `devcontainer` CLI absent | print the generated path + "Reopen in Container" manual steps (don't fail) |
| daemon/proxy down on preflight | EnsureDaemon starts it (as RunAgent); clear error if it can't |
| `--container` but no Docker runtime | `sandbox.NewEngine`/Detect error surfaced clearly; mcp-wrap falls back? No — explicit error (user asked for container) |
| no `--container` | unchanged host-child behavior (backward compatible) |

## Testing

- **`internal/devcontainer`:** `Generate` returns valid JSON with the expected `image`, `containerEnv` (HTTPS_PROXY → host.docker.internal:port, CA vars, REDACTR_BOUND), `mounts` (CA ro), `runArgs` (hardening + add-host). Round-trip `json.Unmarshal` to confirm validity.
- **`redactr code`:** with a fake command-runner + a stubbed launch policy, writes the file (assert content), refuses to clobber without `--force`, and invokes `devcontainer up --workspace-folder` (assert argv) when the CLI "exists" (seam).
- **sandbox `StdioRunArgs`:** argv contains `run --rm -i` (NOT `-it`), the hardening flags, the injection flags, image-before-entrypoint; `Spec.Validate` now accepts `ModeStdioAttached`.
- **`redactr-mcp-wrap`:** a small `wrapTarget(args) (name string, argv []string)` helper returns the host cmd unchanged without `--container`, and the container argv (via StdioRunArgs) with `--container` — unit-tested without running Docker. The MITM loop (`ScanMessage`) is already tested in `internal/mcpwrap`.
- **Deferred (documented):** real `devcontainer up` / VS Code attach / `docker run -i` MCP server.

## Build order (D tasks)

1. `internal/devcontainer.Generate` (devcontainer.json from policy + CA).
2. `redactr code` CLI (preflight + write file + invoke devcontainer CLI via runner seam) + main.go dispatch.
3. Sandbox `StdioRunArgs` + `Spec.Validate` accepts `ModeStdioAttached` (argv test).
4. `redactr-mcp-wrap --container` wiring (`wrapTarget` helper + flag) — backward compatible.

## Out of scope / SEAMs

- Real VS Code attach / `devcontainer up` execution (deferred; generation + invocation argv tested).
- Cursor / non-VS-Code editors (the Dev Container path generalizes to them later — architecture noted).
- `workspace-remote` mode as a first-class sandbox.Launch (D uses file-generation + the devcontainer CLI; a deeper VS Code remote integration is future work).
- Pinning the MCP-server image to a signed `ref@digest` from A3 policy — `redactr-mcp-wrap` uses the policy image when daemon-enrolled, falls back to `redactr-base:local` (a `// SEAM`).
