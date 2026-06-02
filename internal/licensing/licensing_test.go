package licensing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func generateTestKeypair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return key, pubPEM
}

func signToken(t *testing.T, key *ecdsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload

	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestDemoLicenseValid(t *testing.T) {
	mgr, err := NewManager(DevPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	if !mgr.Valid() {
		t.Fatal("demo license should be valid")
	}
	claims := mgr.GetClaims()
	if claims == nil {
		t.Fatal("claims should not be nil")
	}
	if !claims.Demo {
		t.Error("demo flag should be true")
	}
	if claims.Sub != "demo" {
		t.Errorf("sub = %q, want demo", claims.Sub)
	}
}

func TestDemoLicenseFeatures(t *testing.T) {
	mgr, err := NewManager(DevPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	if !mgr.HasFeature("opf") {
		t.Error("demo license should include opf feature")
	}
	if !mgr.HasFeature("premium_support") {
		t.Error("demo license should include premium_support feature")
	}
	if mgr.HasFeature("nonexistent") {
		t.Error("should not have nonexistent feature")
	}
}

func TestValidPaidLicense(t *testing.T) {
	key, pubPEM := generateTestKeypair(t)
	token := signToken(t, key, map[string]interface{}{
		"sub":      "customer-123",
		"features": []string{"opf"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"demo":     false,
	})

	mgr, err := NewManager(pubPEM, token)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	if !mgr.Valid() {
		t.Fatal("paid license should be valid")
	}
	claims := mgr.GetClaims()
	if claims.Sub != "customer-123" {
		t.Errorf("sub = %q, want customer-123", claims.Sub)
	}
	if claims.Demo {
		t.Error("paid license should not be demo")
	}
	if !mgr.HasFeature("opf") {
		t.Error("should have opf feature")
	}
	if mgr.HasFeature("premium_support") {
		t.Error("should not have premium_support (not in token)")
	}
}

func TestExpiredLicense(t *testing.T) {
	key, pubPEM := generateTestKeypair(t)
	token := signToken(t, key, map[string]interface{}{
		"sub":      "expired-user",
		"features": []string{"opf"},
		"iat":      time.Now().Add(-48 * time.Hour).Unix(),
		"exp":      time.Now().Add(-1 * time.Hour).Unix(),
	})

	mgr, err := NewManager(pubPEM, token)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	if mgr.Valid() {
		t.Fatal("expired license should not be valid")
	}
	if mgr.HasFeature("opf") {
		t.Error("expired license should not grant features")
	}
}

func TestTamperedToken(t *testing.T) {
	key, pubPEM := generateTestKeypair(t)
	token := signToken(t, key, map[string]interface{}{
		"sub":      "customer-123",
		"features": []string{"opf"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	// Tamper with the payload — change sub to "hacker"
	parts := strings.SplitN(token, ".", 3)
	tamperedClaims := map[string]interface{}{
		"sub":      "hacker",
		"features": []string{"opf", "premium_support", "admin"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(999 * 24 * time.Hour).Unix(),
	}
	claimsJSON, _ := json.Marshal(tamperedClaims)
	parts[1] = base64.RawURLEncoding.EncodeToString(claimsJSON)
	tampered := strings.Join(parts, ".")

	mgr, err := NewManager(pubPEM, tampered)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	if mgr.Valid() {
		t.Fatal("tampered token should not be valid")
	}
}

func TestWrongKey(t *testing.T) {
	signingKey, _ := generateTestKeypair(t)
	_, wrongPubPEM := generateTestKeypair(t)

	token := signToken(t, signingKey, map[string]interface{}{
		"sub":      "customer",
		"features": []string{"opf"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	mgr, err := NewManager(wrongPubPEM, token)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	if mgr.Valid() {
		t.Fatal("token signed with wrong key should not be valid")
	}
}

func TestRefresh(t *testing.T) {
	key, pubPEM := generateTestKeypair(t)
	token1 := signToken(t, key, map[string]interface{}{
		"sub":      "customer",
		"features": []string{"opf"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
	})

	mgr, err := NewManager(pubPEM, token1)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	if !mgr.HasFeature("opf") {
		t.Error("should have opf after initial token")
	}
	if mgr.HasFeature("premium_support") {
		t.Error("should not have premium_support in initial token")
	}

	token2 := signToken(t, key, map[string]interface{}{
		"sub":      "customer",
		"features": []string{"opf", "premium_support"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	if err := mgr.Refresh(token2); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if !mgr.HasFeature("premium_support") {
		t.Error("should have premium_support after refresh")
	}
}

func TestRefreshWithExpiredToken(t *testing.T) {
	key, pubPEM := generateTestKeypair(t)
	token1 := signToken(t, key, map[string]interface{}{
		"sub":      "customer",
		"features": []string{"opf"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
	})

	mgr, err := NewManager(pubPEM, token1)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	expired := signToken(t, key, map[string]interface{}{
		"sub":      "customer",
		"features": []string{"opf"},
		"iat":      time.Now().Add(-48 * time.Hour).Unix(),
		"exp":      time.Now().Add(-1 * time.Hour).Unix(),
	})

	err = mgr.Refresh(expired)
	if err == nil {
		t.Fatal("refresh with expired token should fail")
	}
	if mgr.Valid() {
		t.Error("license should be invalid after failed refresh")
	}
}

func TestGarbageToken(t *testing.T) {
	_, pubPEM := generateTestKeypair(t)

	mgr, err := NewManager(pubPEM, "not.a.jwt")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	if mgr.Valid() {
		t.Fatal("garbage token should not be valid")
	}
}

func TestBadPublicKey(t *testing.T) {
	_, err := NewManager("not a pem key", DemoToken)
	if err == nil {
		t.Fatal("bad public key should return error")
	}
}

func TestClaimsReturnsCopy(t *testing.T) {
	mgr, err := NewManager(DevPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	c1 := mgr.GetClaims()
	c1.Sub = "mutated"
	c2 := mgr.GetClaims()
	if c2.Sub == "mutated" {
		t.Error("GetClaims should return a copy, not a reference")
	}
}
