//go:build windows

package lifecycle

import (
	"log/slog"
	"time"
)

type Options struct {
	GraceTimeout time.Duration
	IsOurProcess func(pid int) bool
}

type Lock struct{}

type Cleaner interface {
	Unredirect() error
	Cleanup() error
}

func AcquireSingleton(stateDir string, logger *slog.Logger, opts Options) (*Lock, error) {
	return &Lock{}, nil
}

func (l *Lock) Release() error { return nil }

func ReapOrphans(stateDir string, fw Cleaner, logger *slog.Logger) error { return nil }
