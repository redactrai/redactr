// Package config loads the redactr-server configuration from the environment
// with fail-fast validation in production mode. It is intentionally
// dependency-light (stdlib + bcrypt) to avoid import cycles with the packages
// that consume it; richer types (e.g. auth.OIDCConfig) are mapped in main.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// OIDCSettings holds the relying-party configuration for SSO login.
type OIDCSettings struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// Config is the fully-resolved server configuration.
type Config struct {
	DevMode         bool
	Addr            string
	PublicURL       string // external https base URL (prod)
	DBPath          string
	KeyDir          string
	OIDC            *OIDCSettings // nil unless fully configured
	SuperadminUser  string
	SuperadminHash  string // bcrypt hash (may be derived from plaintext)
	SessionTTL      time.Duration
	MachineKey      string
	BackupDir       string
	BackupRetain    int
	AuditRetainDays int
	MaxBodyBytes    int64
	Registry        string
	CosignKey       string
	Secure          bool // cookie Secure flag = !DevMode
}

// Defaults.
const (
	defaultAddr            = ":8080"
	defaultDBPath          = "./redactr-server.db"
	defaultKeyDir          = "./keys"
	defaultSuperadminUser  = "admin"
	defaultSessionTTL      = 12 * time.Hour
	defaultBackupDir       = "./backups"
	defaultBackupRetain    = 14
	defaultAuditRetainDays = 365
	defaultMaxBodyBytes    = int64(1 << 20) // 1048576
	defaultCosignKey       = "./keys/cosign.key"
)

func boolEnv(v string) bool { return v == "1" || v == "true" }

func strDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Load reads config via the injected getenv (os.Getenv in prod, a map in
// tests). It returns an aggregated error listing ALL problems when validation
// fails. In DevMode, prod validation (https + auth requirements) is skipped and
// numeric parse failures fall back to defaults with a warning.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		DevMode:        boolEnv(getenv("REDACTR_DEV_MODE")),
		Addr:           strDefault(getenv("REDACTR_SERVER_ADDR"), defaultAddr),
		PublicURL:      getenv("REDACTR_PUBLIC_URL"),
		DBPath:         strDefault(getenv("REDACTR_SERVER_DB"), defaultDBPath),
		KeyDir:         strDefault(getenv("REDACTR_SERVER_KEY_DIR"), defaultKeyDir),
		SuperadminUser: strDefault(getenv("REDACTR_SUPERADMIN_USER"), defaultSuperadminUser),
		SuperadminHash: getenv("REDACTR_SUPERADMIN_PASSWORD_HASH"),
		MachineKey:     getenv("REDACTR_MACHINE_KEY"),
		BackupDir:      strDefault(getenv("REDACTR_BACKUP_DIR"), defaultBackupDir),
		Registry:       getenv("REDACTR_REGISTRY"),
		CosignKey:      strDefault(getenv("REDACTR_COSIGN_KEY"), defaultCosignKey),
	}
	cfg.Secure = !cfg.DevMode

	var errs []error

	// Plaintext password → bcrypt hash (only if no hash provided).
	if cfg.SuperadminHash == "" {
		if pw := getenv("REDACTR_SUPERADMIN_PASSWORD"); pw != "" {
			h, herr := bcrypt.GenerateFromPassword([]byte(pw), 12)
			if herr != nil {
				errs = append(errs, fmt.Errorf("REDACTR_SUPERADMIN_PASSWORD: bcrypt: %w", herr))
			} else {
				cfg.SuperadminHash = string(h)
				slog.Warn("derived bcrypt hash from REDACTR_SUPERADMIN_PASSWORD; prefer setting REDACTR_SUPERADMIN_PASSWORD_HASH directly")
			}
		}
	}

	// SessionTTL.
	if v := getenv("REDACTR_SESSION_TTL"); v == "" {
		cfg.SessionTTL = defaultSessionTTL
	} else if d, perr := time.ParseDuration(v); perr == nil {
		cfg.SessionTTL = d
	} else {
		cfg.SessionTTL = defaultSessionTTL
		if cfg.DevMode {
			slog.Warn("REDACTR_SESSION_TTL did not parse; using default", "value", v, "default", defaultSessionTTL)
		} else {
			errs = append(errs, fmt.Errorf("REDACTR_SESSION_TTL: invalid duration %q", v))
		}
	}

	cfg.BackupRetain = parseIntBound(getenv, "REDACTR_BACKUP_RETAIN", defaultBackupRetain, 1, cfg.DevMode, &errs)
	cfg.AuditRetainDays = parseIntBound(getenv, "REDACTR_AUDIT_RETAIN_DAYS", defaultAuditRetainDays, 1, cfg.DevMode, &errs)
	cfg.MaxBodyBytes = parseInt64Bound(getenv, "REDACTR_MAX_BODY_BYTES", defaultMaxBodyBytes, 1, cfg.DevMode, &errs)

	// OIDC: configured only if issuer+clientid+secret all present.
	issuer := getenv("REDACTR_OIDC_ISSUER")
	clientID := getenv("REDACTR_OIDC_CLIENT_ID")
	clientSecret := getenv("REDACTR_OIDC_CLIENT_SECRET")
	if issuer != "" && clientID != "" && clientSecret != "" {
		redirect := getenv("REDACTR_OIDC_REDIRECT_URL")
		if redirect == "" {
			redirect = cfg.PublicURL + "/admin/oidc/callback"
		}
		cfg.OIDC = &OIDCSettings{
			Issuer:       issuer,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirect,
		}
	}

	// Prod-only validation.
	if !cfg.DevMode {
		// 1. PublicURL must be non-empty https URL.
		if cfg.PublicURL == "" {
			errs = append(errs, errors.New("REDACTR_PUBLIC_URL: required in prod (must be an https URL)"))
		} else if u, uerr := url.Parse(cfg.PublicURL); uerr != nil {
			errs = append(errs, fmt.Errorf("REDACTR_PUBLIC_URL: invalid URL %q: %w", cfg.PublicURL, uerr))
		} else if u.Scheme != "https" {
			errs = append(errs, fmt.Errorf("REDACTR_PUBLIC_URL: scheme must be https, got %q", u.Scheme))
		}

		// 2. At least one auth method configured.
		if cfg.SuperadminHash == "" && cfg.OIDC == nil {
			errs = append(errs, errors.New("no auth method configured: set REDACTR_SUPERADMIN_PASSWORD_HASH (or _PASSWORD) and/or OIDC (REDACTR_OIDC_ISSUER/_CLIENT_ID/_CLIENT_SECRET)"))
		}
	}

	if len(errs) > 0 {
		return cfg, fmt.Errorf("invalid configuration:\n%w", errors.Join(errs...))
	}
	return cfg, nil
}

// parseIntBound parses key as an int >= min. On empty it returns def. On parse
// failure or out-of-bounds: in dev mode it warns and returns def, in prod it
// appends an error and returns def.
func parseIntBound(getenv func(string) string, key string, def, min int, dev bool, errs *[]error) int {
	v := getenv(key)
	if v == "" {
		return def
	}
	n, perr := strconv.Atoi(v)
	if perr == nil && n >= min {
		return n
	}
	if dev {
		slog.Warn("invalid value; using default", "key", key, "value", v, "default", def)
		return def
	}
	*errs = append(*errs, fmt.Errorf("%s: must be an integer >= %d, got %q", key, min, v))
	return def
}

func parseInt64Bound(getenv func(string) string, key string, def, min int64, dev bool, errs *[]error) int64 {
	v := getenv(key)
	if v == "" {
		return def
	}
	n, perr := strconv.ParseInt(v, 10, 64)
	if perr == nil && n >= min {
		return n
	}
	if dev {
		slog.Warn("invalid value; using default", "key", key, "value", v, "default", def)
		return def
	}
	*errs = append(*errs, fmt.Errorf("%s: must be an integer >= %d, got %q", key, min, v))
	return def
}
