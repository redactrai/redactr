package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := NewSigner(testKey(t))
	tok, err := s.Sign(Claims{DeviceID: "dev1", OrgID: "org1", IssuedAt: 123})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.DeviceID != "dev1" || got.OrgID != "org1" || got.IssuedAt != 123 {
		t.Errorf("claims = %+v", got)
	}
}

func TestVerifyRejectsTamperAndForeignKey(t *testing.T) {
	s := NewSigner(testKey(t))
	tok, _ := s.Sign(Claims{DeviceID: "dev1", OrgID: "org1", IssuedAt: 1})

	parts := strings.SplitN(tok, ".", 2)
	if _, err := s.Verify("x" + parts[0][1:] + "." + parts[1]); err == nil {
		t.Error("expected tampered token to fail")
	}
	other := NewSigner(testKey(t))
	if _, err := other.Verify(tok); err == nil {
		t.Error("expected foreign-key verify to fail")
	}
	if _, err := s.Verify("garbage"); err == nil {
		t.Error("expected malformed token to fail")
	}
}
