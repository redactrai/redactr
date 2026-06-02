package licensing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoLicense     = errors.New("no license configured")
	ErrInvalidToken  = errors.New("invalid license token")
	ErrTokenExpired  = errors.New("license expired")
	ErrBadSignature  = errors.New("license signature verification failed")
	ErrFeatureLocked = errors.New("feature not included in license")
)

// Claims are the verified fields from a license JWT.
type Claims struct {
	Sub      string   `json:"sub"`
	Features []string `json:"features"`
	IssuedAt int64    `json:"iat"`
	ExpiresAt int64   `json:"exp"`
	Demo     bool     `json:"demo"`
}

func (c *Claims) HasFeature(f string) bool {
	for _, feat := range c.Features {
		if feat == f {
			return true
		}
	}
	return false
}

func (c *Claims) Expired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// Manager holds the current license state and runs background validation.
type Manager struct {
	mu     sync.RWMutex
	claims *Claims
	pubKey *ecdsa.PublicKey
	valid  bool
	err    error
	stopCh chan struct{}
}

// NewManager creates a license manager. It verifies the token immediately
// and starts a background goroutine that re-checks expiry periodically.
func NewManager(pubKeyPEM string, token string) (*Manager, error) {
	pub, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("licensing: bad public key: %w", err)
	}

	m := &Manager{
		pubKey: pub,
		stopCh: make(chan struct{}),
	}

	if token == "" {
		token = DemoToken
		slog.Info("no license key configured, using demo license",
			"event", "license_demo",
		)
	}

	claims, err := m.verify(token)
	if err != nil {
		m.err = err
		m.valid = false
		slog.Warn("license verification failed",
			"event", "license_invalid",
			"error", err.Error(),
		)
	} else {
		m.claims = claims
		m.valid = true
		tier := "paid"
		if claims.Demo {
			tier = "demo"
		}
		slog.Info("license activated",
			"event", "license_activated",
			"customer", claims.Sub,
			"tier", tier,
			"features", claims.Features,
			"expires", time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339),
		)
	}

	go m.expiryWatcher()

	return m, nil
}

// HasFeature returns true if the license is valid and includes the feature.
func (m *Manager) HasFeature(feature string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.valid && m.claims != nil && m.claims.HasFeature(feature)
}

// Valid returns whether the current license is valid.
func (m *Manager) Valid() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.valid
}

// Claims returns a copy of the current claims, or nil if invalid.
func (m *Manager) GetClaims() *Claims {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.claims == nil {
		return nil
	}
	cp := *m.claims
	return &cp
}

// Refresh re-verifies a new token (e.g. fetched from a license server).
func (m *Manager) Refresh(token string) error {
	claims, err := m.verify(token)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.valid = false
		m.err = err
		slog.Warn("license refresh failed",
			"event", "license_refresh_failed",
			"error", err.Error(),
		)
		return err
	}
	m.claims = claims
	m.valid = true
	m.err = nil
	slog.Info("license refreshed",
		"event", "license_refreshed",
		"customer", claims.Sub,
		"expires", time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339),
	)
	return nil
}

// Stop shuts down the background expiry watcher.
func (m *Manager) Stop() {
	close(m.stopCh)
}

func (m *Manager) expiryWatcher() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.mu.Lock()
			if m.claims != nil && m.claims.Expired() && m.valid {
				m.valid = false
				m.err = ErrTokenExpired
				slog.Warn("license expired",
					"event", "license_expired",
					"customer", m.claims.Sub,
				)
			}
			m.mu.Unlock()
		}
	}
}

// verify parses a JWT, checks the ES256 signature, and validates expiry.
func (m *Manager) verify(token string) (*Claims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrInvalidToken
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidToken, header.Alg)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrBadSignature
	}
	if len(sigBytes) != 64 {
		return nil, ErrBadSignature
	}

	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(m.pubKey, hash[:], r, s) {
		return nil, ErrBadSignature
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if claims.Expired() {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

func parsePublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() {
		return nil, errors.New("key is not ECDSA P-256")
	}
	return ecPub, nil
}
