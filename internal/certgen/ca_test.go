package certgen

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := GenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	if ca.Cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if ca.Key == nil {
		t.Fatal("expected non-nil private key")
	}
	if !ca.Cert.IsCA {
		t.Error("expected CA certificate")
	}
	if ca.Cert.Subject.CommonName != "Redactr CA" {
		t.Errorf("expected CN 'Redactr CA', got %q", ca.Cert.Subject.CommonName)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("expected cert file written to disk")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("expected key file written to disk")
	}
}

func TestLoadExistingCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	original, err := GenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA() error: %v", err)
	}

	if loaded.Cert.SerialNumber.Cmp(original.Cert.SerialNumber) != 0 {
		t.Error("expected same serial number after reload")
	}
}

func TestLoadOrCreateCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca1, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA() error: %v", err)
	}

	ca2, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("second LoadOrCreateCA() error: %v", err)
	}

	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) != 0 {
		t.Error("expected same CA on second load")
	}
}

func TestIssueCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := GenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	tlsCert, err := ca.IssueCert("api.anthropic.com")
	if err != nil {
		t.Fatalf("IssueCert() error: %v", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	if err := leaf.VerifyHostname("api.anthropic.com"); err != nil {
		t.Errorf("expected cert valid for api.anthropic.com: %v", err)
	}

	pool := x509.NewCertPool()
	certPEM, _ := os.ReadFile(certPath)
	pool.AppendCertsFromPEM(certPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("expected cert verifiable against CA: %v", err)
	}
}
