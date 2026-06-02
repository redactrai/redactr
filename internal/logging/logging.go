package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

func Setup(cfg Config) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var w io.Writer
	switch cfg.Output {
	case "", "stdout":
		w = os.Stdout
	case "stderr":
		w = os.Stderr
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		w = f
	}

	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger, nil
}
