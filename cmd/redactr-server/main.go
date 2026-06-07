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

	"github.com/redactrai/redactr/internal/server/auth"
	"github.com/redactrai/redactr/internal/server/config"
	"github.com/redactrai/redactr/internal/server/httpapi"
	"github.com/redactrai/redactr/internal/server/imagebuild"
	"github.com/redactrai/redactr/internal/server/keys"
	"github.com/redactrai/redactr/internal/server/maint"
	"github.com/redactrai/redactr/internal/server/store"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	priv, err := keys.LoadOrCreate(cfg.KeyDir)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}

	authCfg := httpapi.AuthConfig{
		SuperadminUser: cfg.SuperadminUser,
		SuperadminHash: cfg.SuperadminHash,
		Secure:         cfg.Secure,
		SessionTTL:     cfg.SessionTTL,
		MachineKey:     cfg.MachineKey,
		MaxBodyBytes:   cfg.MaxBodyBytes,
	}
	if cfg.SuperadminHash == "" && cfg.OIDC == nil {
		slog.Warn("no superadmin hash and no OIDC configured — admin login is disabled")
	}

	var oidcRP *auth.OIDC
	if cfg.OIDC != nil {
		oidcRP, err = auth.NewOIDC(context.Background(), auth.OIDCConfig{
			Issuer:       cfg.OIDC.Issuer,
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			RedirectURL:  cfg.OIDC.RedirectURL,
		})
		if err != nil {
			log.Fatalf("oidc: %v", err)
		}
	}

	handler := httpapi.New(st, auth.NewSigner(priv), authCfg, oidcRP)
	if cfg.Registry != "" {
		handler.SetBuilder(imagebuild.NewShellBuilder(cfg.CosignKey), cfg.Registry)
	}

	// Cancel ctx on SIGINT/SIGTERM; drives both the maintenance loop and
	// graceful HTTP shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go maint.Loop(ctx, st, maint.Config{
		BackupDir:       cfg.BackupDir,
		BackupRetain:    cfg.BackupRetain,
		AuditRetainDays: cfg.AuditRetainDays,
		Interval:        24 * time.Hour,
	}, slog.Default(), time.Now)

	// TLS is terminated by the reverse proxy; we serve plain HTTP here.
	srv := &http.Server{Addr: cfg.Addr, Handler: handler}

	go func() {
		slog.Info("redactr-server listening", "addr", cfg.Addr, "dev_mode", cfg.DevMode)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown signal received; draining")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}
