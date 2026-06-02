//go:build unix

// Package lifecycle owns redactr's startup-time process supervision:
// singleton enforcement (one redactr per machine via flock pidfile) and
// orphan reaping (sidecar processes and pf rules left from a crash).
package lifecycle

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rakeshguha/redactr/internal/firewall"
)

const (
	pidfileName        = "redactr.pid"
	defaultGrace       = 5 * time.Second
	sidecarReapGrace   = 3 * time.Second
	processProbeTickMs = 50
)

// Options configures AcquireSingleton. Zero values use safe defaults.
type Options struct {
	GraceTimeout time.Duration
	IsOurProcess func(pid int) bool
}

// Lock represents an acquired singleton lock. Release on graceful shutdown.
type Lock struct {
	path string
	file *os.File
}

// Cleaner is the subset of firewall.Manager that ReapOrphans needs.
type Cleaner interface {
	Unredirect() error
	Cleanup() error
}

// AcquireSingleton claims the pidfile lock, replacing any live predecessor.
func AcquireSingleton(stateDir string, logger *slog.Logger, opts Options) (*Lock, error) {
	if opts.GraceTimeout == 0 {
		opts.GraceTimeout = defaultGrace
	}
	if opts.IsOurProcess == nil {
		opts.IsOurProcess = isRedactrProcess
	}
	if logger == nil {
		logger = slog.Default()
	}

	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	path := filepath.Join(stateDir, pidfileName)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open pidfile: %w", err)
	}

	if err := tryFlock(f); err == nil {
		if oldPid, ok := readPid(path); ok && oldPid != os.Getpid() {
			logger.Info("stale pidfile reclaimed",
				"event", "lifecycle_stale_pidfile_reclaimed",
				"prev_pid", oldPid,
			)
		}
		return finalizeClaim(f, path, logger)
	} else if !errors.Is(err, syscall.EWOULDBLOCK) {
		f.Close()
		return nil, fmt.Errorf("flock: %w", err)
	}

	predecessorPid, ok := readPid(path)
	if !ok {
		f.Close()
		return nil, fmt.Errorf("pidfile %s is locked but unparseable", path)
	}
	if predecessorPid == os.Getpid() {
		f.Close()
		return nil, fmt.Errorf("pidfile already held by current process")
	}
	if !opts.IsOurProcess(predecessorPid) {
		f.Close()
		return nil, fmt.Errorf(
			"pidfile %s points at pid %d which is not a redactr process; "+
				"refusing to kill — investigate manually",
			path, predecessorPid,
		)
	}

	logger.Info("replacing predecessor",
		"event", "lifecycle_replace_start",
		"predecessor_pid", predecessorPid,
		"grace_ms", opts.GraceTimeout.Milliseconds(),
	)
	if err := terminateAndWait(predecessorPid, opts.GraceTimeout, logger); err != nil {
		f.Close()
		return nil, fmt.Errorf("terminate predecessor pid %d: %w", predecessorPid, err)
	}
	logger.Info("predecessor terminated",
		"event", "lifecycle_replace_done",
		"predecessor_pid", predecessorPid,
	)

	if err := tryFlock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("flock after replace: %w", err)
	}
	return finalizeClaim(f, path, logger)
}

// Release unlocks and closes the pidfile. The file is intentionally not
// unlinked, to keep the inode stable for the next acquirer.
func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}

// ReapOrphans cleans up state from a crashed predecessor: GLiNER sidecar
// process and pf rules. Best-effort; logs and returns first error.
func ReapOrphans(stateDir string, fw Cleaner, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	var firstErr error

	if pid, ok := findSidecarPid(stateDir); ok {
		if processAlive(pid) {
			logger.Info("reaping orphaned sidecar",
				"event", "lifecycle_reap_sidecar",
				"pid", pid,
			)
			if err := terminateAndWait(pid, sidecarReapGrace, logger); err != nil {
				logger.Warn("sidecar reap failed",
					"event", "lifecycle_reap_sidecar_failed",
					"pid", pid,
					"error", err.Error(),
				)
				firstErr = err
			}
		}
		_ = os.Remove(filepath.Join(stateDir, "sidecar.port"))
	}

	if fw != nil {
		if err := fw.Unredirect(); err != nil && !errors.Is(err, firewall.ErrNotImplemented) {
			logger.Warn("orphan unredirect failed",
				"event", "lifecycle_reap_unredirect_failed",
				"error", err.Error(),
			)
			if firstErr == nil {
				firstErr = err
			}
		}
		if err := fw.Cleanup(); err != nil && !errors.Is(err, firewall.ErrNotImplemented) {
			logger.Warn("orphan firewall cleanup failed",
				"event", "lifecycle_reap_firewall_failed",
				"error", err.Error(),
			)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

func tryFlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func finalizeClaim(f *os.File, path string, logger *slog.Logger) (*Lock, error) {
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
		f.Close()
		return nil, err
	}
	logger.Info("singleton lock acquired",
		"event", "lifecycle_lock_acquired",
		"pid", os.Getpid(),
		"pidfile", path,
	)
	return &Lock{path: path, file: f}, nil
}

func terminateAndWait(pid int, grace time.Duration, logger *slog.Logger) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("sigterm: %w", err)
	}

	tick := processProbeTickMs * time.Millisecond
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(tick)
	}

	logger.Warn("predecessor ignored SIGTERM, sending SIGKILL",
		"event", "lifecycle_sigkill",
		"pid", pid,
	)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("sigkill: %w", err)
	}
	for i := 0; i < 40; i++ {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(tick)
	}
	return fmt.Errorf("pid %d still alive after SIGKILL", pid)
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return !errors.Is(err, syscall.ESRCH)
}

func readPid(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if line == "" {
		return 0, false
	}
	pid, err := strconv.Atoi(line)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func findSidecarPid(stateDir string) (int, bool) {
	data, err := os.ReadFile(filepath.Join(stateDir, "sidecar.port"))
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || port <= 0 {
		return 0, false
	}
	out, err := exec.Command("lsof", "-tiTCP:"+strconv.Itoa(port), "-sTCP:LISTEN").Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if pid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil && pid > 0 {
			return pid, true
		}
	}
	return 0, false
}

func isRedactrProcess(pid int) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	comm := strings.ToLower(strings.TrimSpace(string(out)))
	if comm == "" {
		return false
	}
	base := comm
	if idx := strings.LastIndex(comm, "/"); idx >= 0 {
		base = comm[idx+1:]
	}
	return strings.Contains(base, "redactr") || base == "go"
}
