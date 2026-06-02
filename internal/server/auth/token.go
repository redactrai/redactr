// Package auth handles device enrollment, device-token signing/verification,
// and HTTP auth middleware for the control-plane server.
package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/rakeshguha/redactr/internal/signing"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrBadSignature = errors.New("bad signature")
)

// Claims is the device bearer-token payload.
type Claims struct {
	DeviceID string `json:"device_id"`
	OrgID    string `json:"org_id"`
	IssuedAt int64  `json:"issued_at"`
}

// Signer signs and verifies device bearer tokens with an ECDSA P-256 key.
type Signer struct{ priv *ecdsa.PrivateKey }

func NewSigner(priv *ecdsa.PrivateKey) *Signer { return &Signer{priv: priv} }

// Sign returns base64url(claimsJSON) + "." + base64url(r||s).
func (s *Signer) Sign(c Claims) (string, error) {
	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	seg := base64.RawURLEncoding.EncodeToString(claimsJSON)
	hash := sha256.Sum256([]byte(seg))
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, hash[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return seg + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks the signature and returns the claims.
func (s *Signer) Verify(token string) (Claims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return Claims{}, ErrInvalidToken
	}
	hash := sha256.Sum256([]byte(parts[0]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(sig) != 64 {
		return Claims{}, ErrBadSignature
	}
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&s.priv.PublicKey, hash[:], r, ss) {
		return Claims{}, ErrBadSignature
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return Claims{}, ErrInvalidToken
	}
	return c, nil
}

// SignDetached signs an arbitrary payload with the server key (for policy bundles).
func (s *Signer) SignDetached(payload []byte) (string, error) {
	return signing.Sign(s.priv, payload)
}

// PublicKeyPEM returns the server's public key as PKIX PEM (handed to clients).
func (s *Signer) PublicKeyPEM() (string, error) {
	return signing.PublicKeyPEM(s.priv)
}
