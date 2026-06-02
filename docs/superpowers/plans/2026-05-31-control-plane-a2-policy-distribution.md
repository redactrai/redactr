# Policy Distribution (A2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Server-driven, tamper-evident launch policy: admin sets a per-org policy; server distributes it as an ECDSA-signed bundle (ETag/304); the client enrolls, fetches, **verifies the signature**, and refreshes its local `policy.json` — fail-open throughout.

**Architecture:** A shared `internal/signing` leaf (detached ECDSA + PEM). Server: `policies` table + admin PUT/GET + `GET /v1/policy` (signed) + `GET /v1/server-key` + server pubkey in the enroll response (via new `auth.Signer` methods, so A1's `httpapi.New` signature is unchanged). Client: `internal/enrollment` (enrollment.json), a `redactr enroll` CLI, `internal/policysync` (fetch+verify+cache, fail-open), and daemon wiring (sync loop gated on enrollment).

**Tech Stack:** Go 1.26, stdlib crypto/ecdsa, modernc sqlite (already a dep), net/http, httptest.

**Verification bar:** `go build ./...`, `go test ./internal/... ` + full suite green, `go vet ./...`, `CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/ ./internal/server/...` + `GOOS=windows`. macOS host tests green.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/signing/signing.go` (+test) | detached ECDSA sign/verify, PEM helpers |
| `internal/control/control.go` (modify) | add `PolicyBundle`, `SignedPolicy` DTOs |
| `internal/server/auth/token.go` (modify) | add `Signer.SignDetached`, `Signer.PublicKeyPEM` |
| `internal/server/store/store.go` (modify) + schema.sql | `policies` table, `GetPolicy`/`PutPolicy` |
| `internal/server/httpapi/server.go` (modify) | policy routes + server-key + enroll pubkey |
| `internal/enrollment/enrollment.go` (+test) | enrollment.json load/save |
| `internal/cli/enroll.go` (+test) | `RunEnroll` + `redactr enroll` |
| `cmd/redactr/main.go` (modify) | `enroll` subcommand dispatch |
| `internal/policysync/policysync.go` (+test) | fetch+verify+cache, fail-open |
| `internal/daemon/daemon.go` (modify) | sync loop on Start (enrolled-gated) |

---

## Task 1: `internal/signing` + DTOs + Signer methods

**Files:** Create `internal/signing/signing.go`, `internal/signing/signing_test.go`. Modify `internal/control/control.go`, `internal/server/auth/token.go`.

- [ ] **Step 1: failing test (`internal/signing/signing_test.go`)**
```go
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
	// Tamper.
	if err := Verify(&priv.PublicKey, []byte(`{"image":"y"}`), sig); err == nil {
		t.Error("expected tampered payload to fail")
	}
	// Foreign key.
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
```
Run `go test ./internal/signing/ -v` → FAIL.

- [ ] **Step 2: implement `internal/signing/signing.go`**
```go
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
```
Run `go test ./internal/signing/ -v` → PASS.

- [ ] **Step 3: add DTOs to `internal/control/control.go`** (append)
```go
// PolicyBundle is the per-org launch policy distributed by the control plane.
type PolicyBundle struct {
	Image     string   `json:"image"`
	MountMode string   `json:"mountMode"`
	Denylist  []string `json:"denylist"`
	Version   int      `json:"version"`
}

// SignedPolicy is the GET /v1/policy response: a base64url(PolicyBundle JSON)
// plus a detached signature over those JSON bytes.
type SignedPolicy struct {
	Bundle    string `json:"bundle"`    // base64url of the PolicyBundle JSON
	Signature string `json:"signature"` // base64url(r||s)
	Version   int    `json:"version"`
}
```

- [ ] **Step 4: add methods to `internal/server/auth/token.go`** (append; add import `"github.com/redactrai/redactr/internal/signing"`)
```go
// SignDetached signs an arbitrary payload with the server key (for policy bundles).
func (s *Signer) SignDetached(payload []byte) (string, error) {
	return signing.Sign(s.priv, payload)
}

// PublicKeyPEM returns the server's public key as PKIX PEM (handed to clients).
func (s *Signer) PublicKeyPEM() (string, error) {
	return signing.PublicKeyPEM(s.priv)
}
```

- [ ] **Step 5: verify + commit**
Run: `go build ./... && go test ./internal/signing/ ./internal/server/auth/ ./internal/control/ -v && go vet ./internal/signing/ ./internal/control/ ./internal/server/auth/`
```bash
git add internal/signing/ internal/control/control.go internal/server/auth/token.go
git commit -m "feat(signing): detached ECDSA + policy DTOs + Signer.SignDetached/PublicKeyPEM"
```

---

## Task 2: Server store — `policies` table

**Files:** Modify `internal/server/store/schema.sql`, `internal/server/store/store.go`. Test: append to `store_test.go`.

- [ ] **Step 1: add to `schema.sql`**
```sql
CREATE TABLE IF NOT EXISTS policies (
  org_id      TEXT PRIMARY KEY REFERENCES orgs(id),
  bundle_json TEXT NOT NULL,
  version     INTEGER NOT NULL,
  updated_at  TIMESTAMP NOT NULL
);
```

- [ ] **Step 2: failing test (append to `internal/server/store/store_test.go`)**
```go
func TestPolicyGetSeedAndPut(t *testing.T) {
	s := openTest(t)
	org, _ := s.CreateOrg("Acme")

	// Unset → seed (version 0, default image).
	raw, ver, err := s.GetPolicy(org.ID)
	if err != nil || ver != 0 {
		t.Fatalf("GetPolicy seed: ver=%d err=%v", ver, err)
	}
	if !strings.Contains(string(raw), "redactr-base:local") {
		t.Errorf("seed bundle = %s", raw)
	}

	// Put → version 1, then 2.
	v1, err := s.PutPolicy(org.ID, []byte(`{"image":"redactr-base:v2","mountMode":"bind","denylist":["evil.test"]}`))
	if err != nil || v1 != 1 {
		t.Fatalf("PutPolicy#1: v=%d err=%v", v1, err)
	}
	v2, _ := s.PutPolicy(org.ID, []byte(`{"image":"redactr-base:v3","mountMode":"bind","denylist":[]}`))
	if v2 != 2 {
		t.Errorf("PutPolicy#2 v=%d want 2", v2)
	}
	raw, ver, _ = s.GetPolicy(org.ID)
	if ver != 2 || !strings.Contains(string(raw), "redactr-base:v3") {
		t.Errorf("GetPolicy after put: ver=%d raw=%s", ver, raw)
	}
}
```
(Add `"strings"` to the test imports if not present.)

- [ ] **Step 3: implement in `internal/server/store/store.go`** (append; add a seed const)
```go
// seedPolicyJSON is served when an org has no policy set.
const seedPolicyJSON = `{"image":"redactr-base:local","mountMode":"bind","denylist":[]}`

// GetPolicy returns the org's policy bundle JSON and version. If none is set,
// it returns the seed bundle with version 0.
func (s *Store) GetPolicy(orgID string) ([]byte, int, error) {
	var raw string
	var version int
	err := s.db.QueryRow(`SELECT bundle_json,version FROM policies WHERE org_id=?`, orgID).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return []byte(seedPolicyJSON), 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	return []byte(raw), version, nil
}

// PutPolicy upserts the org's policy bundle and bumps its version (1 on first set).
func (s *Store) PutPolicy(orgID string, bundleJSON []byte) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var version int
	err = tx.QueryRow(`SELECT version FROM policies WHERE org_id=?`, orgID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		version = 0
	} else if err != nil {
		return 0, err
	}
	version++
	if _, err := tx.Exec(
		`INSERT INTO policies(org_id,bundle_json,version,updated_at) VALUES(?,?,?,?)
		 ON CONFLICT(org_id) DO UPDATE SET bundle_json=excluded.bundle_json, version=excluded.version, updated_at=excluded.updated_at`,
		orgID, string(bundleJSON), version, time.Now().UTC()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return version, nil
}
```

- [ ] **Step 4: verify + commit**
Run: `go test ./internal/server/store/ -v && go vet ./internal/server/store/ && CGO_ENABLED=0 GOOS=linux go build ./internal/server/store/`
```bash
git add internal/server/store/schema.sql internal/server/store/store.go internal/server/store/store_test.go
git commit -m "feat(server): policies table — GetPolicy (seed default) + versioned PutPolicy"
```

---

## Task 3: Server HTTP — policy routes + server key + enroll pubkey

**Files:** Modify `internal/server/httpapi/server.go`. Test: append to `server_test.go`.

- [ ] **Step 1: failing test (append to `internal/server/httpapi/server_test.go`)**
```go
func TestPolicyDistribution(t *testing.T) {
	ts := newTestServer(t)

	// org + enroll a device.
	r := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct{ ID string `json:"id"` }
	json.NewDecoder(r.Body).Decode(&org); r.Body.Close()
	r = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", "admin-key", map[string]int{"max_uses": 0})
	var mint struct{ Token string `json:"token"` }
	json.NewDecoder(r.Body).Decode(&mint); r.Body.Close()
	r = postJSON(t, ts, "/v1/enroll", "", map[string]string{"enrollment_token": mint.Token, "device_name": "d", "platform": "darwin"})
	var enr map[string]string
	json.NewDecoder(r.Body).Decode(&enr); r.Body.Close()
	if enr["server_public_key"] == "" {
		t.Fatal("enroll response missing server_public_key")
	}

	// Admin sets a policy.
	req, _ := http.NewRequest("PUT", ts.URL+"/admin/orgs/"+org.ID+"/policy", bytes.NewReader([]byte(`{"image":"redactr-base:v9","mountMode":"bind","denylist":["evil.test"]}`)))
	req.Header.Set("X-Admin-Key", "admin-key")
	pr, _ := http.DefaultClient.Do(req); pr.Body.Close()

	// Client GET /v1/policy → signed bundle, verifies with server key, ETag.
	greq, _ := http.NewRequest("GET", ts.URL+"/v1/policy", nil)
	greq.Header.Set("Authorization", "Bearer "+enr["token"])
	gresp, _ := http.DefaultClient.Do(greq)
	if gresp.StatusCode != 200 {
		t.Fatalf("/v1/policy code = %d", gresp.StatusCode)
	}
	etag := gresp.Header.Get("ETag")
	var sp struct{ Bundle, Signature string; Version int }
	json.NewDecoder(gresp.Body).Decode(&sp); gresp.Body.Close()
	if sp.Version != 1 || etag == "" {
		t.Fatalf("version=%d etag=%q", sp.Version, etag)
	}
	pub, err := signing.ParsePublicKeyPEM(enr["server_public_key"])
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	bundleJSON, _ := base64.RawURLEncoding.DecodeString(sp.Bundle)
	if err := signing.Verify(pub, bundleJSON, sp.Signature); err != nil {
		t.Fatalf("bundle signature: %v", err)
	}
	if !bytes.Contains(bundleJSON, []byte("redactr-base:v9")) {
		t.Errorf("bundle = %s", bundleJSON)
	}

	// If-None-Match with current ETag → 304.
	greq2, _ := http.NewRequest("GET", ts.URL+"/v1/policy", nil)
	greq2.Header.Set("Authorization", "Bearer "+enr["token"])
	greq2.Header.Set("If-None-Match", etag)
	g2, _ := http.DefaultClient.Do(greq2)
	if g2.StatusCode != 304 {
		t.Errorf("If-None-Match code = %d, want 304", g2.StatusCode)
	}
	g2.Body.Close()

	// Public server-key endpoint.
	sk, _ := http.Get(ts.URL + "/v1/server-key")
	var skBody struct{ PublicKey string `json:"public_key"` }
	json.NewDecoder(sk.Body).Decode(&skBody); sk.Body.Close()
	if skBody.PublicKey == "" {
		t.Error("server-key empty")
	}
}
```
(Add imports `"encoding/base64"`, `"bytes"`, and `"github.com/redactrai/redactr/internal/signing"` to the test file.)

- [ ] **Step 2: extend `internal/server/httpapi/server.go`**

Add routes in `New` (after the whoami line / among existing):
```go
	s.mux.Handle("GET /v1/policy", dev(http.HandlerFunc(s.handleGetPolicy)))
	s.mux.HandleFunc("GET /v1/server-key", s.handleServerKey)
	s.mux.Handle("PUT /admin/orgs/{id}/policy", admin(http.HandlerFunc(s.handlePutPolicy)))
	s.mux.Handle("GET /admin/orgs/{id}/policy", admin(http.HandlerFunc(s.handleGetAdminPolicy)))
```
(Remove the `// SEAM A2:` comment line.)

Add handlers + extend enroll. Add imports `"encoding/base64"`, `"fmt"`, `"github.com/redactrai/redactr/internal/control"`.
```go
func (s *Server) handleServerKey(w http.ResponseWriter, r *http.Request) {
	pem, err := s.signer.PublicKeyPEM()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]string{"public_key": pem})
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if _, err := s.store.GetOrg(orgID); err != nil {
		http.Error(w, "unknown org", http.StatusNotFound)
		return
	}
	var b control.PolicyBundle
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Image == "" || b.MountMode == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Canonicalize: store only the policy fields (version is authoritative in the table).
	canonical, _ := json.Marshal(control.PolicyBundle{Image: b.Image, MountMode: b.MountMode, Denylist: b.Denylist})
	version, err := s.store.PutPolicy(orgID, canonical)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]int{"version": version})
}

func (s *Server) handleGetAdminPolicy(w http.ResponseWriter, r *http.Request) {
	raw, version, err := s.store.GetPolicy(r.PathValue("id"))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(bundleWithVersion(raw, version))
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	raw, version, err := s.store.GetPolicy(auth.OrgID(r.Context()))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	etag := fmt.Sprintf("\"v%d\"", version)
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	bundleJSON := bundleWithVersion(raw, version) // exact bytes that get signed
	sig, err := s.signer.SignDetached(bundleJSON)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", etag)
	writeJSON(w, 200, control.SignedPolicy{
		Bundle:    base64.RawURLEncoding.EncodeToString(bundleJSON),
		Signature: sig,
		Version:   version,
	})
}

// bundleWithVersion injects the authoritative version into the stored bundle JSON.
func bundleWithVersion(raw []byte, version int) []byte {
	var b control.PolicyBundle
	_ = json.Unmarshal(raw, &b)
	b.Version = version
	out, _ := json.Marshal(b)
	return out
}
```
Extend `handleEnroll`'s success response to include the server public key (replace the existing `writeJSON(w, 200, map[string]string{"device_id":..., "org_id":..., "token":...})` line with):
```go
	pubPEM, _ := s.signer.PublicKeyPEM()
	writeJSON(w, 200, map[string]string{
		"device_id": res.DeviceID, "org_id": res.OrgID, "token": res.Token,
		"server_public_key": pubPEM,
	})
```
The test file (`server_test.go`) does use `bytes` (for `bytes.NewReader`/`bytes.Contains`) — keep `bytes` in the TEST imports, but `server.go` itself does not need `bytes`.

- [ ] **Step 3: verify + commit**
Run: `go test ./internal/server/httpapi/ -v && go vet ./internal/server/httpapi/ && go build ./... && CGO_ENABLED=0 GOOS=linux go build ./internal/server/...`
```bash
git add internal/server/httpapi/server.go internal/server/httpapi/server_test.go
git commit -m "feat(server): signed policy distribution (GET /v1/policy, ETag) + server-key + enroll pubkey"
```

---

## Task 4: `internal/enrollment`

**Files:** Create `internal/enrollment/enrollment.go`, `internal/enrollment/enrollment_test.go`.

- [ ] **Step 1: failing test**
```go
package enrollment

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadExists(t *testing.T) {
	base := t.TempDir()
	if Exists(base) {
		t.Fatal("should not exist yet")
	}
	e := Enrollment{ServerURL: "https://s", DeviceToken: "tok", ServerPublicKey: "PEM", DeviceID: "d", OrgID: "o"}
	if err := Save(base, e); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !Exists(base) {
		t.Fatal("should exist after Save")
	}
	got, err := Load(base)
	if err != nil || got.ServerURL != "https://s" || got.DeviceToken != "tok" || got.OrgID != "o" {
		t.Fatalf("Load = %+v err=%v", got, err)
	}
}
```
Run `go test ./internal/enrollment/ -v` → FAIL.

- [ ] **Step 2: implement `internal/enrollment/enrollment.go`**
```go
// Package enrollment persists the desktop client's control-plane enrollment
// (server URL, device bearer token, and the server's public key) at
// ~/.redactr/enrollment.json.
package enrollment

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Enrollment struct {
	ServerURL       string `json:"server_url"`
	DeviceToken     string `json:"device_token"`
	ServerPublicKey string `json:"server_public_key"`
	DeviceID        string `json:"device_id"`
	OrgID           string `json:"org_id"`
}

func path(baseDir string) string { return filepath.Join(baseDir, "enrollment.json") }

func Exists(baseDir string) bool {
	_, err := os.Stat(path(baseDir))
	return err == nil
}

func Load(baseDir string) (Enrollment, error) {
	raw, err := os.ReadFile(path(baseDir))
	if err != nil {
		return Enrollment{}, err
	}
	var e Enrollment
	return e, json.Unmarshal(raw, &e)
}

func Save(baseDir string, e Enrollment) error {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp := path(baseDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path(baseDir))
}
```
Run → PASS. Commit:
```bash
git add internal/enrollment/
git commit -m "feat(client): enrollment.json persistence (server url, device token, server key)"
```

---

## Task 5: `redactr enroll` CLI

**Files:** Create `internal/cli/enroll.go`, `internal/cli/enroll_test.go`. Modify `cmd/redactr/main.go`.

- [ ] **Step 1: failing test (`internal/cli/enroll_test.go`)** — drives the enroll POST against an httptest server.
```go
package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redactrai/redactr/internal/enrollment"
)

func TestRunEnrollStoresEnrollment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"device_id": "dev1", "org_id": "org1", "token": "bearer-xyz", "server_public_key": "PEMDATA",
		})
	}))
	defer srv.Close()

	base := t.TempDir()
	if err := RunEnroll(base, srv.URL, "enroll-tok"); err != nil {
		t.Fatalf("RunEnroll: %v", err)
	}
	e, err := enrollment.Load(base)
	if err != nil || e.DeviceToken != "bearer-xyz" || e.ServerPublicKey != "PEMDATA" || e.ServerURL != srv.URL || e.OrgID != "org1" {
		t.Fatalf("enrollment = %+v err=%v", e, err)
	}
}
```
Run `go test ./internal/cli/ -run TestRunEnroll -v` → FAIL.

- [ ] **Step 2: implement `internal/cli/enroll.go`**
```go
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/enrollment"
)

// RunEnroll enrolls this device with the control-plane server and stores the
// resulting device token + server public key under baseDir.
func RunEnroll(baseDir, serverURL, enrollToken string) error {
	host, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{
		"enrollment_token": enrollToken,
		"device_name":      host,
		"platform":         runtime.GOOS,
	})
	url := strings.TrimRight(serverURL, "/") + "/v1/enroll"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("enroll request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrollment failed (server returned %d)", resp.StatusCode)
	}
	var out struct {
		DeviceID, OrgID, Token, ServerPublicKey string
	}
	var raw map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	out.DeviceID, out.OrgID, out.Token, out.ServerPublicKey =
		raw["device_id"], raw["org_id"], raw["token"], raw["server_public_key"]
	if out.Token == "" {
		return fmt.Errorf("enrollment response missing token")
	}
	if err := enrollment.Save(baseDir, enrollment.Enrollment{
		ServerURL: strings.TrimRight(serverURL, "/"), DeviceToken: out.Token,
		ServerPublicKey: out.ServerPublicKey, DeviceID: out.DeviceID, OrgID: out.OrgID,
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "enrolled device %s in org %s\n", out.DeviceID, out.OrgID)
	return nil
}
```

- [ ] **Step 3: wire `cmd/redactr/main.go`** — add a `case "enroll":` in the subcommand switch. Add `"flag"` import if not present.
```go
		case "enroll":
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("cannot determine home directory: %v", err)
			}
			fs := flag.NewFlagSet("enroll", flag.ExitOnError)
			server := fs.String("server", "", "control-plane server URL")
			token := fs.String("token", "", "org enrollment token")
			_ = fs.Parse(os.Args[2:])
			if *server == "" || *token == "" {
				log.Fatalf("usage: redactr enroll --server <url> --token <enrollment-token>")
			}
			if err := cli.RunEnroll(filepath.Join(home, ".redactr"), *server, *token); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
```

- [ ] **Step 4: verify + commit**
Run: `go test ./internal/cli/ -v && go build ./... && go vet ./internal/cli/`
```bash
git add internal/cli/enroll.go internal/cli/enroll_test.go cmd/redactr/main.go
git commit -m "feat(cli): redactr enroll — enroll device with control-plane server"
```

---

## Task 6: `internal/policysync`

**Files:** Create `internal/policysync/policysync.go`, `internal/policysync/policysync_test.go`.

- [ ] **Step 1: failing test** — against an httptest server that serves a signed bundle.
```go
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
	// Second sync → 304 → no error, cache intact.
	if err := Sync(base); err != nil {
		t.Fatalf("Sync#2 (304): %v", err)
	}
}

func TestSyncRejectsBadSignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubPEM, _ := signing.PublicKeyPEM(priv)
	bundleJSON, _ := json.Marshal(control.PolicyBundle{Image: "evil:image", MountMode: "bind"})
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badSig, _ := signing.Sign(other, bundleJSON) // signed by the WRONG key

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(control.SignedPolicy{Bundle: base64.RawURLEncoding.EncodeToString(bundleJSON), Signature: badSig, Version: 1})
	}))
	defer srv.Close()

	base := t.TempDir()
	_ = enrollment.Save(base, enrollment.Enrollment{ServerURL: srv.URL, DeviceToken: "tok", ServerPublicKey: pubPEM, OrgID: "o"})
	if err := Sync(base); err == nil {
		t.Fatal("expected bad-signature sync to error")
	}
	// Cache must NOT contain the forged image.
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
```
Run `go test ./internal/policysync/ -v` → FAIL.

- [ ] **Step 2: implement `internal/policysync/policysync.go`**
```go
// Package policysync pulls the signed policy bundle from the control-plane
// server, verifies it against the stored server public key, and refreshes the
// local policy cache. Every failure mode is fail-open: the cached policy is kept.
package policysync

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/control"
	"github.com/redactrai/redactr/internal/enrollment"
	"github.com/redactrai/redactr/internal/policy"
	"github.com/redactrai/redactr/internal/signing"
)

func etagPath(baseDir string) string { return filepath.Join(baseDir, "cache", "policy.etag") }

// Sync fetches and verifies the server policy, refreshing the local cache.
// Returns nil (no-op) if the device is not enrolled. On any network/verify
// failure it returns the error but leaves the cached policy untouched.
func Sync(baseDir string) error {
	if !enrollment.Exists(baseDir) {
		return nil
	}
	enr, err := enrollment.Load(baseDir)
	if err != nil {
		return err
	}
	pub, err := signing.ParsePublicKeyPEM(enr.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("bad stored server key: %w", err)
	}

	req, _ := http.NewRequest(http.MethodGet, strings.TrimRight(enr.ServerURL, "/")+"/v1/policy", nil)
	req.Header.Set("Authorization", "Bearer "+enr.DeviceToken)
	if etag, _ := os.ReadFile(etagPath(baseDir)); len(etag) > 0 {
		req.Header.Set("If-None-Match", string(etag))
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("policy fetch failed: %d", resp.StatusCode)
	}

	var sp control.SignedPolicy
	if err := json.NewDecoder(resp.Body).Decode(&sp); err != nil {
		return err
	}
	bundleJSON, err := base64.RawURLEncoding.DecodeString(sp.Bundle)
	if err != nil {
		return err
	}
	if err := signing.Verify(pub, bundleJSON, sp.Signature); err != nil {
		return fmt.Errorf("policy signature rejected: %w", err) // forged/tampered — cache untouched
	}

	var b control.PolicyBundle
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		return err
	}
	if err := policy.Save(baseDir, policy.Policy{
		Image: b.Image, MountMode: b.MountMode, Denylist: b.Denylist, Version: b.Version, FetchedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		_ = os.MkdirAll(filepath.Dir(etagPath(baseDir)), 0o755)
		_ = os.WriteFile(etagPath(baseDir), []byte(etag), 0o644)
	}
	return nil
}
```
Run → PASS. Commit:
```bash
git add internal/policysync/
git commit -m "feat(client): policysync — fetch+verify signed policy into the cache (fail-open)"
```

---

## Task 7: Daemon wiring

**Files:** Modify `internal/daemon/daemon.go`. Test: append to `daemon_test.go`.

- [ ] **Step 1: failing test (append to `internal/daemon/daemon_test.go`)** — proves the enrolled gate calls sync; unenrolled is a no-op.
```go
func TestPolicySyncGate(t *testing.T) {
	base := t.TempDir()
	// Not enrolled → shouldSyncPolicy false.
	if shouldSyncPolicy(base) {
		t.Error("unenrolled should not sync")
	}
}
```
Run `go test ./internal/daemon/ -run TestPolicySyncGate -v` → FAIL (undefined: shouldSyncPolicy).

- [ ] **Step 2: implement in `internal/daemon/daemon.go`**

Add the import `"github.com/redactrai/redactr/internal/enrollment"` and `"github.com/redactrai/redactr/internal/policysync"` and `"time"`/`"context"` (already imported). Add a helper + a sync loop started in `Start` (gated on `!Ephemeral` and enrollment), cancelled in `Stop`.
```go
// shouldSyncPolicy reports whether this daemon should run the policy-sync loop.
func shouldSyncPolicy(baseDir string) bool {
	return enrollment.Exists(baseDir)
}
```
Add a field `policyCancel context.CancelFunc` to the `Daemon` struct. In `Start`, after the control socket starts, add:
```go
	if !d.opts.Ephemeral && shouldSyncPolicy(d.opts.BaseDir) {
		ctx, cancel := context.WithCancel(context.Background())
		d.policyCancel = cancel
		go d.policySyncLoop(ctx)
	}
```
Add the loop method:
```go
func (d *Daemon) policySyncLoop(ctx context.Context) {
	_ = policysync.Sync(d.opts.BaseDir) // initial sync; fail-open
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := policysync.Sync(d.opts.BaseDir); err != nil {
				slog.Warn("policy sync failed (keeping cached policy)", "error", err)
			}
		}
	}
}
```
In `Stop`, before/after the control-socket stop, add:
```go
	if d.policyCancel != nil {
		d.policyCancel()
	}
```
(`slog` is already imported in daemon.go.)

- [ ] **Step 3: verify + commit**
Run: `go test ./internal/daemon/ -v && go build ./... && go vet ./internal/daemon/ && go test ./internal/... 2>&1 | grep -v "no test files"`
```bash
git add internal/daemon/daemon.go internal/daemon/daemon_test.go
git commit -m "feat(daemon): policy-sync loop on start (enrolled-gated, fail-open)"
```

---

## Final verification
```bash
go build ./... && go test ./internal/... 2>&1 | grep -v "no test files" && go vet ./... \
  && CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/ ./internal/server/... \
  && CGO_ENABLED=0 GOOS=windows go build ./cmd/redactr-server/ ./internal/server/...
```
All green; both cross-compiles succeed.

## Self-Review map
- signing+DTOs+Signer methods → T1; policies store → T2; signed HTTP distribution+server-key+enroll pubkey → T3; enrollment.json → T4; `redactr enroll` → T5; policysync verify+cache (incl. bad-sig rejection) → T6; daemon sync loop → T7. Fail-open + signature rejection are tested (T6). SEAM A3 (ref@digest) left as a future bundle field.
