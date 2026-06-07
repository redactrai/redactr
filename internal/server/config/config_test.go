package config

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// mapEnv returns a getenv func backed by m.
func mapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func validBcrypt(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func TestConfigFailFastInProd(t *testing.T) {
	_, err := Load(mapEnv(map[string]string{
		"REDACTR_PUBLIC_URL": "http://x",
	}))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "https") {
		t.Errorf("error should mention https problem: %q", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "auth") {
		t.Errorf("error should mention no-auth problem: %q", msg)
	}
}

func TestConfigDevModePermissive(t *testing.T) {
	cfg, err := Load(mapEnv(map[string]string{
		"REDACTR_DEV_MODE": "1",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.DevMode {
		t.Error("DevMode should be true")
	}
	if cfg.Secure {
		t.Error("Secure should be false in dev mode")
	}
	if cfg.MaxBodyBytes != 1048576 {
		t.Errorf("MaxBodyBytes = %d, want 1048576", cfg.MaxBodyBytes)
	}
	if cfg.BackupRetain != 14 {
		t.Errorf("BackupRetain = %d, want 14", cfg.BackupRetain)
	}
	if cfg.AuditRetainDays != 365 {
		t.Errorf("AuditRetainDays = %d, want 365", cfg.AuditRetainDays)
	}
}

func TestConfigProdHappySuperadmin(t *testing.T) {
	hash := validBcrypt(t, "s3cret")
	cfg, err := Load(mapEnv(map[string]string{
		"REDACTR_PUBLIC_URL":               "https://redactr.example.com",
		"REDACTR_SUPERADMIN_USER":          "boss",
		"REDACTR_SUPERADMIN_PASSWORD_HASH": hash,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Secure {
		t.Error("Secure should be true in prod")
	}
	if cfg.OIDC != nil {
		t.Error("OIDC should be nil")
	}
	if cfg.SuperadminUser != "boss" {
		t.Errorf("SuperadminUser = %q", cfg.SuperadminUser)
	}
	if cfg.SuperadminHash != hash {
		t.Error("SuperadminHash mismatch")
	}
}

func TestConfigProdHappyOIDC(t *testing.T) {
	cfg, err := Load(mapEnv(map[string]string{
		"REDACTR_PUBLIC_URL":         "https://redactr.example.com",
		"REDACTR_OIDC_ISSUER":        "https://accounts.example.com",
		"REDACTR_OIDC_CLIENT_ID":     "cid",
		"REDACTR_OIDC_CLIENT_SECRET": "csecret",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OIDC == nil {
		t.Fatal("OIDC should be non-nil")
	}
	want := "https://redactr.example.com/admin/oidc/callback"
	if cfg.OIDC.RedirectURL != want {
		t.Errorf("RedirectURL = %q, want %q", cfg.OIDC.RedirectURL, want)
	}
}

func TestConfigPlaintextPasswordHashed(t *testing.T) {
	cfg, err := Load(mapEnv(map[string]string{
		"REDACTR_PUBLIC_URL":          "https://redactr.example.com",
		"REDACTR_SUPERADMIN_PASSWORD": "hunter2",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SuperadminHash == "" {
		t.Fatal("SuperadminHash should be set")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.SuperadminHash), []byte("hunter2")); err != nil {
		t.Errorf("hash does not match plaintext: %v", err)
	}
}

func TestConfigBadDuration(t *testing.T) {
	_, err := Load(mapEnv(map[string]string{
		"REDACTR_PUBLIC_URL":               "https://redactr.example.com",
		"REDACTR_SUPERADMIN_PASSWORD_HASH": validBcrypt(t, "x"),
		"REDACTR_SESSION_TTL":              "nonsense",
	}))
	if err == nil {
		t.Fatal("expected error for bad duration")
	}
	if !strings.Contains(err.Error(), "REDACTR_SESSION_TTL") {
		t.Errorf("error should mention REDACTR_SESSION_TTL: %q", err.Error())
	}
}
