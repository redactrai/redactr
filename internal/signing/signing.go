// Package signing provides detached ECDSA-P256 signatures over a payload and
// PEM (de)serialization of the public key. Shared by the control-plane server
// (signs with its private key) and the desktop client (verifies with the
// server's public key).
package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
)

// Sign returns base64url(r||s) of an ECDSA signature over sha256(payload).
func Sign(priv *ecdsa.PrivateKey, payload []byte) (string, error) {
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify checks a base64url(r||s) signature over sha256(payload).
func Verify(pub *ecdsa.PublicKey, payload []byte, sigB64 string) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return errors.New("bad signature encoding")
	}
	h := sha256.Sum256(payload)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, h[:], r, s) {
		return errors.New("signature verification failed")
	}
	return nil
}

// PublicKeyPEM marshals the public key of priv as a PKIX PEM string.
func PublicKeyPEM(priv *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// ParsePublicKeyPEM parses a PKIX PEM public key, requiring ECDSA P-256.
func ParsePublicKeyPEM(s string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not an ECDSA P-256 public key")
	}
	return ec, nil
}
