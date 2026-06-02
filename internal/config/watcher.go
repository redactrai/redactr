package config

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	mgr     *Manager
	onLoad  func(*Config)
	stopCh  chan struct{}
}

func NewWatcher(mgr *Manager, onLoad func(*Config)) *Watcher {
	return &Watcher{
		mgr:    mgr,
		onLoad: onLoad,
		stopCh: make(chan struct{}),
	}
}

func (w *Watcher) Start() error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := fsw.Add(w.mgr.Path()); err != nil {
		fsw.Close()
		return err
	}

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	go w.loop(fsw, sighup)
	return nil
}

func (w *Watcher) Stop() {
	close(w.stopCh)
}

func (w *Watcher) loop(fsw *fsnotify.Watcher, sighup chan os.Signal) {
	defer fsw.Close()

	// Debounce: editors often write multiple events for a single save.
	var debounce *time.Timer

	reload := func(source string) {
		cfg, err := w.mgr.Reload()
		if err != nil {
			slog.Warn("config reload failed, keeping current config",
				"event", "config_reload_failed",
				"source", source,
				"error", err.Error(),
			)
			return
		}
		slog.Info("config reloaded",
			"event", "config_reloaded",
			"source", source,
			"path", w.mgr.Path(),
		)
		if w.onLoad != nil {
			w.onLoad(cfg)
		}
	}

	for {
		select {
		case <-w.stopCh:
			return
		case <-sighup:
			reload("sighup")
		case event, ok := <-fsw.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(200*time.Millisecond, func() {
				reload("fsnotify")
			})
		case err, ok := <-fsw.Errors:
			if !ok {
				return
			}
			slog.Warn("config watcher error", "error", err)
		}
	}
}
