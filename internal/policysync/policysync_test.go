package policysync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/enrollment"
	"github.com/redactrai/redactr/internal/policy"
	"github.com/redactrai/redactr/internal/signing"
)

func TestSyncVerifiesAndWritesPolicy(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubPEM, _ := signing.PublicKeyPEM(priv)
	bundleJSON, _ := json.Marshal(control.PolicyBundle{Image: "redactr-base:v9", MountMode: "bind", Denylist: []string{"evil.test"}, Version: 3})
	sig, _ := signing.Sign(priv, bundleJSON)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v3"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v3"`)
		json.NewEncoder(w).Encode(control.SignedPolicy{
			Bundle: base64.RawURLEncoding.EncodeToString(bundleJSON), Signature: sig, Version: 3,
		})
	}))
	defer srv.Close()

	base := t.TempDir()
	_ = enrollment.Save(base, enrollment.Enrollment{ServerURL: srv.URL, DeviceToken: "tok", ServerPublicKey: pubPEM, OrgID: "o", DeviceID: "d"})

	if err := Sync(base); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	p, _ := policy.Load(base, nil)
	if p.Image != "redactr-base:v9" || len(p.Denylist) != 1 {
		t.Fatalf("policy not written: %+v", p)
	}
	if err := Sync(base); err != nil {
		t.Fatalf("Sync#2 (304): %v", err)
	}
}

func TestSyncRejectsBadSignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubPEM, _ := signing.PublicKeyPEM(priv)
	bundleJSON, _ := json.Marshal(control.PolicyBundle{Image: "evil:image", MountMode: "bind"})
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badSig, _ := signing.Sign(other, bundleJSON)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(control.SignedPolicy{Bundle: base64.RawURLEncoding.EncodeToString(bundleJSON), Signature: badSig, Version: 1})
	}))
	defer srv.Close()

	base := t.TempDir()
	_ = enrollment.Save(base, enrollment.Enrollment{ServerURL: srv.URL, DeviceToken: "tok", ServerPublicKey: pubPEM, OrgID: "o"})
	if err := Sync(base); err == nil {
		t.Fatal("expected bad-signature sync to error")
	}
	p, _ := policy.Load(base, nil)
	if p.Image == "evil:image" {
		t.Fatal("forged bundle was written despite bad signature")
	}
}

func TestSyncNoEnrollmentIsNoop(t *testing.T) {
	if err := Sync(t.TempDir()); err != nil {
		t.Errorf("unenrolled Sync should be a no-op, got %v", err)
	}
}
