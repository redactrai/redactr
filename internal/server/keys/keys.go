// Package keys loads or generates the control-plane server's ECDSA P-256
// signing keypair, persisted as PEM on disk.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

// LoadOrCreate returns the server private key from <dir>/server.key, generating
// and persisting a new P-256 key if the file does not exist.
func LoadOrCreate(dir string) (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "server.key")
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("server.key: no PEM block")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if key.Curve != elliptic.P256() {
			return nil, errors.New("server.key: expected P-256 key")
		}
		return key, nil
	case errors.Is(err, os.ErrNotExist):
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
			return nil, err
		}
		return priv, nil
	default:
		return nil, err
	}
}
