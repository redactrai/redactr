// Package maint runs periodic maintenance on the server store: nightly
// SQLite backups and audit/event row retention sweeps.
package maint

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/server/store"
)

// Config holds tunable parameters for the maintenance loop.
type Config struct {
	BackupDir       string        // directory where timestamped backups are written
	BackupRetain    int           // keep the newest N backup files (must be >= 1)
	AuditRetainDays int           // delete audit/event rows older than this many days
	Interval        time.Duration // period between maintenance cycles (e.g. 24h)
}

const backupLayout = "20060102-150405"
const backupPrefix = "redactr-"
const backupSuffix = ".db"

// Loop runs maintenance cycles until ctx is cancelled. The first cycle runs
// immediately; subsequent cycles run every cfg.Interval. Cycle errors are
// logged but do not terminate the loop.
func Loop(ctx context.Context, st *store.Store, cfg Config, logger *slog.Logger, now func() time.Time) {
	if err := runCycle(st, cfg, logger, now); err != nil {
		logger.Error("maint cycle error", "err", err)
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := runCycle(st, cfg, logger, now); err != nil {
				logger.Error("maint cycle error", "err", err)
			}
		}
	}
}

// RunCycle is exported so tests can invoke a single cycle directly.
func RunCycle(st *store.Store, cfg Config, logger *slog.Logger, now func() time.Time) error {
	return runCycle(st, cfg, logger, now)
}

// runCycle performs one backup + retention pass.
//
// Ordering:
//  1. Ensure BackupDir exists.
//  2. Write a VACUUM INTO backup (timestamped filename).
//  3. Prune old backup FILES to keep the newest BackupRetain (file-prune
//     errors are logged but do not abort step 4).
//  4. Prune old DB rows via PruneOlderThan.
//  5. Sweep expired session rows via SweepExpiredSessions.
func runCycle(st *store.Store, cfg Config, logger *slog.Logger, now func() time.Time) error {
	t := now()

	// 1. Ensure the backup directory exists.
	if err := os.MkdirAll(cfg.BackupDir, 0o750); err != nil {
		return fmt.Errorf("maint: create backup dir: %w", err)
	}

	// 2. Write backup.
	name := backupPrefix + t.Format(backupLayout) + backupSuffix
	backupPath := filepath.Join(cfg.BackupDir, name)
	backupErr := st.BackupTo(backupPath)
	if backupErr != nil {
		logger.Error("maint: backup failed", "path", backupPath, "err", backupErr)
		// Continue to row retention even if backup fails.
	}

	// 3. Prune old backup files (best-effort; errors logged, not returned).
	retain := cfg.BackupRetain
	if retain < 1 {
		retain = 1
	}
	filesPruned, filePruneErr := PruneBackups(cfg.BackupDir, retain)
	if filePruneErr != nil {
		logger.Warn("maint: backup file prune error", "err", filePruneErr)
	}

	// 4. Prune old rows.
	cutoff := t.AddDate(0, 0, -cfg.AuditRetainDays)
	rowsPruned, rowErr := st.PruneOlderThan(cutoff)
	if rowErr != nil {
		logger.Error("maint: row prune failed", "err", rowErr)
	}

	// 5. Sweep expired session rows (unbounded growth otherwise).
	sessionsSwept, sessErr := st.SweepExpiredSessions()
	if sessErr != nil {
		logger.Error("maint: session sweep failed", "err", sessErr)
	} else {
		logger.Info("maint: swept expired sessions", "count", sessionsSwept)
	}

	logger.Info("maint: cycle complete",
		"backup", backupPath,
		"files_pruned", filesPruned,
		"rows_pruned", rowsPruned,
		"sessions_swept", sessionsSwept,
		"cutoff", cutoff.Format(time.RFC3339),
	)

	// Return the first hard error (backup, row prune, or session sweep).
	// File-prune errors are non-fatal (best effort) and only logged.
	if backupErr != nil {
		return backupErr
	}
	if rowErr != nil {
		return rowErr
	}
	return sessErr
}

// PruneBackups removes all but the newest `retain` backup files
// (files matching redactr-*.db) from dir. It returns the count of deleted
// files. Because backup filenames embed a sortable timestamp
// (YYYYMMDD-HHMMSS), lexicographic order equals chronological order.
//
// PruneBackups is exported so tests can exercise it directly.
func PruneBackups(dir string, retain int) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("maint: list backup dir: %w", err)
	}

	// Collect only files matching our backup naming pattern.
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, backupPrefix) && strings.HasSuffix(n, backupSuffix) {
			files = append(files, n)
		}
	}

	// Sort ascending (oldest first) — lexicographic == chronological for our layout.
	sort.Strings(files)

	if len(files) <= retain {
		return 0, nil
	}

	toDelete := files[:len(files)-retain]
	var pruned int
	for _, name := range toDelete {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return pruned, fmt.Errorf("maint: remove backup %s: %w", name, err)
		}
		pruned++
	}
	return pruned, nil
}
