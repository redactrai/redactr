package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k
}

func TestSignVerifyDetached(t *testing.T) {
	priv := key(t)
	payload := []byte(`{"image":"x"}`)
	sig, err := Sign(priv, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(&priv.PublicKey, payload, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := Verify(&priv.PublicKey, []byte(`{"image":"y"}`), sig); err == nil {
		t.Error("expected tampered payload to fail")
	}
	if err := Verify(&key(t).PublicKey, payload, sig); err == nil {
		t.Error("expected foreign key to fail")
	}
}

func TestPublicKeyPEMRoundTrip(t *testing.T) {
	priv := key(t)
	pemStr, err := PublicKeyPEM(priv)
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	pub, err := ParsePublicKeyPEM(pemStr)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("pubkey round-trip mismatch")
	}
}
