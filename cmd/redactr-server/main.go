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
	"github.com/redactrai/redactr/internal/server/httpapi"
	"github.com/redactrai/redactr/internal/server/imagebuild"
	"github.com/redactrai/redactr/internal/server/keys"
	"github.com/redactrai/redactr/internal/server/store"
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

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	priv, err := keys.LoadOrCreate(keyDir)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}

	sessionTTL := 12 * time.Hour
	if v := os.Getenv("REDACTR_SESSION_TTL"); v != "" {
		if d, derr := time.ParseDuration(v); derr == nil {
			sessionTTL = d
		}
	}
	authCfg := httpapi.AuthConfig{
		SuperadminUser: env("REDACTR_SUPERADMIN_USER", "admin"),
		SuperadminHash: os.Getenv("REDACTR_SUPERADMIN_HASH"), // bcrypt hash; empty disables password login
		Secure:         os.Getenv("REDACTR_COOKIE_SECURE") != "",
		SessionTTL:     sessionTTL,
		MachineKey:     os.Getenv("REDACTR_MACHINE_KEY"), // optional; enables X-Machine-Key on enrollment-token minting
		MaxBodyBytes:   1 << 20,
	}
	if authCfg.SuperadminHash == "" && os.Getenv("REDACTR_OIDC_ISSUER") == "" {
		slog.Warn("no REDACTR_SUPERADMIN_HASH and no OIDC configured — admin login is disabled")
	}

	var oidcRP *auth.OIDC
	if issuer := os.Getenv("REDACTR_OIDC_ISSUER"); issuer != "" {
		oidcRP, err = auth.NewOIDC(context.Background(), auth.OIDCConfig{
			Issuer:       issuer,
			ClientID:     os.Getenv("REDACTR_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("REDACTR_OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("REDACTR_OIDC_REDIRECT_URL"),
		})
		if err != nil {
			log.Fatalf("oidc: %v", err)
		}
	}

	handler := httpapi.New(st, auth.NewSigner(priv), authCfg, oidcRP)
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
