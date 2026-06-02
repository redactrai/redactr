// Command redactr-server is the Redactr v2 control-plane server.
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rakeshguha/redactr/internal/server/auth"
	"github.com/rakeshguha/redactr/internal/server/httpapi"
	"github.com/rakeshguha/redactr/internal/server/imagebuild"
	"github.com/rakeshguha/redactr/internal/server/keys"
	"github.com/rakeshguha/redactr/internal/server/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("REDACTR_SERVER_ADDR", ":8080")
	dbPath := env("REDACTR_SERVER_DB", "./redactr-server.db")
	keyDir := env("REDACTR_SERVER_KEY_DIR", "./keys")

	adminKey := os.Getenv("REDACTR_ADMIN_KEY")
	if adminKey == "" {
		adminKey = httpapi.NewRawToken()
		slog.Warn("no REDACTR_ADMIN_KEY set — generated one (set it to persist across restarts)", "admin_key", adminKey)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	priv, err := keys.LoadOrCreate(keyDir)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}

	handler := httpapi.New(st, auth.NewSigner(priv), adminKey)
	if reg := os.Getenv("REDACTR_REGISTRY"); reg != "" {
		handler.SetBuilder(imagebuild.NewShellBuilder(env("REDACTR_COSIGN_KEY", "./keys/cosign.key")), reg)
	}
	srv := &http.Server{Addr: addr, Handler: handler}

	go func() {
		slog.Info("redactr-server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
