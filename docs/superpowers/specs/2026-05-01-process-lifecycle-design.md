# Process lifecycle: singleton + self-heal

## Problem

`go run ./cmd/redactr` does not currently know about prior instances. Symptoms users hit:

1. Stop a running redactr poorly (Ctrl+C the `go run` parent but the compiled child survives) and the next `go run` fails on `bind: address already in use`.
2. `kill -9` redactr and orphans remain: the GLiNER python sidecar keeps running, and pf redirect rules linger so traffic is mis-routed until `redactr cleanup` is invoked manually.

Goal: a single `go run ./cmd/redactr` (or `redactr`) always produces a clean, ready process. No manual `pkill`, no manual `redactr cleanup`.

## Design

### Approach

Pidfile + advisory file lock (`flock`). On startup:

1. **Acquire singleton.** Open `~/.redactr/state/redactr.pid`, attempt `flock(LOCK_EX|LOCK_NB)`.
   - If it succeeds, claim — write our PID, proceed.
   - If it fails (predecessor alive), read the predecessor's PID, verify it is a redactr process (PID-reuse defense via `ps -p PID -o comm=`), send `SIGTERM`, poll for the lock with a 5s grace, escalate to `SIGKILL` on timeout, then claim.
2. **Reap orphans.** After acquiring the lock and before starting any server:
   - If `~/.redactr/state/sidecar.port` references a live listener, find its PID via `lsof -tiTCP:<port> -sTCP:LISTEN` and `SIGTERM`/`SIGKILL` it.
   - Call `firewall.Manager.Unredirect()` and `Cleanup()` to flush any pf rules left from a crashed predecessor (these are idempotent — already used by `redactr cleanup`).
3. **Release on shutdown.** Existing graceful shutdown defers a `Lock.Release()` that unlocks and closes the file. The pidfile is intentionally not unlinked — leaves the file as a stable inode that the next acquirer can flock against, avoiding a race where a successor flocks an unlinked ghost inode.

Rejected alternatives:
- **Port-probe** (try to bind admin port 9090, query `/health` if busy): brittle (port may not be redactr), gives no PID for hard-kill, doesn't help orphan reaping.
- **Wrapping supervisor process**: more code, doesn't make next-startup any cleaner than the pidfile approach.

### Component boundary

New package `internal/lifecycle`:

```go
type Lock struct { /* unexported */ }

type Options struct {
    GraceTimeout time.Duration       // default 5s
    IsOurProcess func(pid int) bool  // default: ps comm contains "redactr" or "go"
}

func AcquireSingleton(stateDir string, logger *slog.Logger, opts Options) (*Lock, error)
func (l *Lock) Release() error

type Cleaner interface {
    Unredirect() error
    Cleanup() error
}
func ReapOrphans(stateDir string, fw Cleaner, logger *slog.Logger) error
```

`cmd/redactr/main.go` calls these in order at startup, before any server starts:

```go
lock, err := lifecycle.AcquireSingleton(stateDir, logger, lifecycle.Options{})
if err != nil { log.Fatal(err) }
defer lock.Release()

if err := lifecycle.ReapOrphans(stateDir, fwMgr, logger); err != nil {
    slog.Warn("orphan reap had errors", "error", err)
    // continue — singleton lock guarantees no conflict with a live peer
}
```

`Options.IsOurProcess` is pluggable to make tests possible (real predecessors are scarce in unit tests).

### Failure modes

| Case | Behavior |
|---|---|
| No pidfile | Create + claim. |
| Pidfile, predecessor alive, comm matches | SIGTERM → 5s grace → SIGKILL → claim. |
| Pidfile, predecessor alive, comm does **not** match (PID reuse) | Refuse with explicit error pointing user to investigate; do not kill. |
| Pidfile, predecessor dead (crashed without Release) | OS released flock, our flock succeeds — claim, log "stale pidfile". |
| Predecessor ignores SIGTERM | SIGKILL after 5s, log warn. |
| `ReapOrphans` fails partially | Log warns, continue startup. The singleton lock is the binding correctness invariant; orphan reaping is best-effort cleanup. |
| `firewall.ErrNotImplemented` (Linux/Windows) | Treated as success, no log noise. |

### Platform scope

`flock`, `syscall.Kill`, and `ps` are available on darwin and linux. Windows is out of scope for this round — guard the implementation with `//go:build unix` and provide a no-op `Acquire`/`Release` on Windows so the binary still builds.

### Testing

- **Unit (`AcquireSingleton`):**
  - No pidfile → claim succeeds; PID written to file.
  - Stale pidfile (PID of dead process) → claim succeeds.
  - Predecessor alive, `IsOurProcess` returns true, predecessor responds to SIGTERM (fork `sh -c 'sleep 30'`) → predecessor dies, claim succeeds.
  - Predecessor alive, ignores SIGTERM (`sh -c "trap '' TERM; sleep 30"`) → SIGKILL path, claim succeeds.
  - Predecessor alive, `IsOurProcess` returns false → returns error containing PID; predecessor untouched.
- **Unit (`ReapOrphans`):** spawn fake sidecar bound to a port, write port to `sidecar.port`, run reap, assert process is dead and file removed; passing a no-op `Cleaner` confirms it doesn't touch firewall on test envs.
- **Manual smoke:** `go run ./cmd/redactr` then a second `go run ./cmd/redactr` in another terminal — second should report "replacing predecessor" and start cleanly.
