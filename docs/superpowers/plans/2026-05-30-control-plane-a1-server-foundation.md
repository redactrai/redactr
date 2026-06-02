# Control-Plane Server Foundation (A1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up `cmd/redactr-server` — a deployable Go control-plane with embedded SQLite, multi-tenant orgs/devices/enrollment-tokens, device enrollment issuing ECDSA-signed bearer tokens, an auth middleware that injects org/device context, and an admin-key-guarded management API.

**Architecture:** A new `internal/server/*` package tree + `cmd/redactr-server`. The store is pure-Go SQLite (`modernc.org/sqlite`, no CGo). Device tokens reuse the `internal/licensing` ECDSA-P256 / ES256 scheme. Everything is pure-Go and unit-tested against a temp-file SQLite per test — no external services. A2–A5 hang off the `RequireDevice` middleware and org context via documented SEAMs.

**Tech Stack:** Go 1.26, `modernc.org/sqlite` (new dep), stdlib `crypto/ecdsa`/`crypto/sha256`/`database/sql`/`net/http` (Go 1.22 method-pattern mux).

**Verification bar:** `go build ./...`, `go test ./internal/server/... ` + full existing macOS suite green, `go vet ./...` clean, and `CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/ ./internal/server/...` + `GOOS=windows` clean (modernc sqlite is pure-Go).

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/server/store/schema.sql` | embedded DDL (orgs, enrollment_tokens, devices) |
| `internal/server/store/store.go` | SQLite open + migrate; org/token/device CRUD; transactional `EnrollDevice` |
| `internal/server/keys/keys.go` | load-or-generate ECDSA P-256 keypair (PEM on disk) |
| `internal/server/auth/token.go` | device-token `Signer` (sign/verify), `Claims` |
| `internal/server/auth/enroll.go` | enrollment orchestration (hash token, call store, issue token) |
| `internal/server/auth/middleware.go` | `RequireDevice`, `RequireAdmin`, context helpers |
| `internal/server/httpapi/server.go` | `Server`, routes, handlers |
| `cmd/redactr-server/main.go` | config, wiring, serve + graceful shutdown |

---

## Task 1: Store (SQLite + schema + CRUD + transactional enroll)

**Files:**
- Create: `internal/server/store/schema.sql`, `internal/server/store/store.go`, `internal/server/store/store_test.go`
- Modify: `go.mod`/`go.sum` (add `modernc.org/sqlite`)

- [ ] **Step 1: Add the dependency**

Run: `go get modernc.org/sqlite@latest`
Expected: `go.mod` gains `modernc.org/sqlite`. (Pure Go; cross-compiles.)

- [ ] **Step 2: Create the schema (`internal/server/store/schema.sql`)**

```sql
CREATE TABLE IF NOT EXISTS orgs (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token_hash  TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES orgs(id),
  expires_at  TIMESTAMP NOT NULL,
  max_uses    INTEGER NOT NULL,
  used_count  INTEGER NOT NULL DEFAULT 0,
  revoked     INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL REFERENCES orgs(id),
  name          TEXT NOT NULL,
  platform      TEXT NOT NULL,
  enrolled_at   TIMESTAMP NOT NULL,
  last_seen_at  TIMESTAMP,
  revoked       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_devices_org ON devices(org_id);
```

- [ ] **Step 3: Write the failing test (`internal/server/store/store_test.go`)**

```go
package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOrgAndTokenAndDeviceCRUD(t *testing.T) {
	s := openTest(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	org, err := s.CreateOrg("Acme")
	if err != nil || org.ID == "" || org.Name != "Acme" {
		t.Fatalf("CreateOrg: %+v err=%v", org, err)
	}
	orgs, err := s.ListOrgs()
	if err != nil || len(orgs) != 1 {
		t.Fatalf("ListOrgs: %v len=%d", err, len(orgs))
	}

	if err := s.CreateEnrollmentToken("HASH1", org.ID, now.Add(time.Hour), 2, now); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	// First enroll succeeds and increments used_count.
	d1, err := s.EnrollDevice("HASH1", "laptop", "darwin", now)
	if err != nil || d1.ID == "" || d1.OrgID != org.ID {
		t.Fatalf("EnrollDevice#1: %+v err=%v", d1, err)
	}
	d2, err := s.EnrollDevice("HASH1", "laptop2", "windows", now)
	if err != nil {
		t.Fatalf("EnrollDevice#2: %v", err)
	}
	// Third exceeds max_uses=2 → ErrEnrollment.
	if _, err := s.EnrollDevice("HASH1", "laptop3", "linux", now); err != ErrEnrollment {
		t.Fatalf("EnrollDevice#3 err = %v, want ErrEnrollment", err)
	}

	got, err := s.GetDevice(d1.ID)
	if err != nil || got.Revoked {
		t.Fatalf("GetDevice: %+v err=%v", got, err)
	}
	if err := s.RevokeDevice(d1.ID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	got, _ = s.GetDevice(d1.ID)
	if !got.Revoked {
		t.Errorf("device should be revoked")
	}
	devs, err := s.ListDevices(org.ID)
	if err != nil || len(devs) != 2 {
		t.Fatalf("ListDevices: %v len=%d", err, len(devs))
	}
	_ = d2
}

func TestEnrollExpiredAndRevokedToken(t *testing.T) {
	s := openTest(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	org, _ := s.CreateOrg("Acme")

	// Expired token.
	_ = s.CreateEnrollmentToken("EXP", org.ID, now.Add(-time.Hour), 0, now)
	if _, err := s.EnrollDevice("EXP", "d", "darwin", now); err != ErrEnrollment {
		t.Errorf("expired token err = %v, want ErrEnrollment", err)
	}
	// Unknown token.
	if _, err := s.EnrollDevice("NOPE", "d", "darwin", now); err != ErrEnrollment {
		t.Errorf("unknown token err = %v, want ErrEnrollment", err)
	}
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `go test ./internal/server/store/ -v`
Expected: FAIL — package does not compile (`undefined: Open`).

- [ ] **Step 5: Implement `internal/server/store/store.go`**

```go
// Package store is the control-plane server's embedded SQLite datastore:
// orgs, enrollment tokens, and devices.
package store

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// ErrEnrollment is returned when an enrollment token is invalid (unknown,
// expired, revoked, or exhausted). Deliberately generic — no oracle on which.
var ErrEnrollment = errors.New("enrollment failed")

type Store struct{ db *sql.DB }

type Org struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

type Device struct {
	ID         string
	OrgID      string
	Name       string
	Platform   string
	EnrolledAt time.Time
	LastSeenAt *time.Time
	Revoked    bool
}

// Open opens (creating if needed) the SQLite database at path and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// newID returns a random 128-bit hex identifier.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Store) CreateOrg(name string) (Org, error) {
	o := Org{ID: newID(), Name: name, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO orgs(id,name,created_at) VALUES(?,?,?)`, o.ID, o.Name, o.CreatedAt)
	return o, err
}

func (s *Store) ListOrgs() ([]Org, error) {
	rows, err := s.db.Query(`SELECT id,name,created_at FROM orgs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Name, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) GetOrg(id string) (Org, error) {
	var o Org
	err := s.db.QueryRow(`SELECT id,name,created_at FROM orgs WHERE id=?`, id).Scan(&o.ID, &o.Name, &o.CreatedAt)
	return o, err
}

func (s *Store) CreateEnrollmentToken(tokenHash, orgID string, expiresAt time.Time, maxUses int, now time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO enrollment_tokens(token_hash,org_id,expires_at,max_uses,used_count,revoked,created_at)
		 VALUES(?,?,?,?,0,0,?)`,
		tokenHash, orgID, expiresAt, maxUses, now)
	return err
}

// EnrollDevice atomically validates the token (exists, not revoked, not expired,
// used_count < max_uses or max_uses == 0), inserts a device, and increments
// used_count. Returns ErrEnrollment if the token is invalid.
func (s *Store) EnrollDevice(tokenHash, name, platform string, now time.Time) (Device, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()

	var orgID string
	var expiresAt time.Time
	var maxUses, usedCount, revoked int
	err = tx.QueryRow(
		`SELECT org_id,expires_at,max_uses,used_count,revoked FROM enrollment_tokens WHERE token_hash=?`,
		tokenHash).Scan(&orgID, &expiresAt, &maxUses, &usedCount, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrEnrollment
	}
	if err != nil {
		return Device{}, err
	}
	if revoked != 0 || now.After(expiresAt) || (maxUses != 0 && usedCount >= maxUses) {
		return Device{}, ErrEnrollment
	}

	d := Device{ID: newID(), OrgID: orgID, Name: name, Platform: platform, EnrolledAt: now}
	if _, err := tx.Exec(
		`INSERT INTO devices(id,org_id,name,platform,enrolled_at,revoked) VALUES(?,?,?,?,?,0)`,
		d.ID, d.OrgID, d.Name, d.Platform, d.EnrolledAt); err != nil {
		return Device{}, err
	}
	if _, err := tx.Exec(`UPDATE enrollment_tokens SET used_count=used_count+1 WHERE token_hash=?`, tokenHash); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	return d, nil
}

func (s *Store) GetDevice(id string) (Device, error) {
	var d Device
	var last sql.NullTime
	var revoked int
	err := s.db.QueryRow(
		`SELECT id,org_id,name,platform,enrolled_at,last_seen_at,revoked FROM devices WHERE id=?`, id).
		Scan(&d.ID, &d.OrgID, &d.Name, &d.Platform, &d.EnrolledAt, &last, &revoked)
	if err != nil {
		return Device{}, err
	}
	if last.Valid {
		d.LastSeenAt = &last.Time
	}
	d.Revoked = revoked != 0
	return d, nil
}

func (s *Store) ListDevices(orgID string) ([]Device, error) {
	rows, err := s.db.Query(
		`SELECT id,org_id,name,platform,enrolled_at,last_seen_at,revoked FROM devices WHERE org_id=? ORDER BY enrolled_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var last sql.NullTime
		var revoked int
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Name, &d.Platform, &d.EnrolledAt, &last, &revoked); err != nil {
			return nil, err
		}
		if last.Valid {
			d.LastSeenAt = &last.Time
		}
		d.Revoked = revoked != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RevokeDevice(id string) error {
	_, err := s.db.Exec(`UPDATE devices SET revoked=1 WHERE id=?`, id)
	return err
}

func (s *Store) TouchDevice(id string, t time.Time) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen_at=? WHERE id=?`, t, id)
	return err
}
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/server/store/ -v && go vet ./internal/server/store/`
Expected: both tests PASS; vet clean.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/server/store/
git commit -m "feat(server): SQLite store — orgs, enrollment tokens, transactional device enroll"
```

---

## Task 2: ECDSA keypair load-or-generate

**Files:**
- Create: `internal/server/keys/keys.go`, `internal/server/keys/keys_test.go`

- [ ] **Step 1: Write the failing test (`internal/server/keys/keys_test.go`)**

```go
package keys

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate#1: %v", err)
	}
	if k1 == nil || k1.Curve == nil {
		t.Fatal("nil key")
	}
	// Second call loads the same key from disk.
	k2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate#2: %v", err)
	}
	if k1.D.Cmp(k2.D) != 0 {
		t.Error("expected the same private key on reload")
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `go test ./internal/server/keys/ -v`
Expected: FAIL — `undefined: LoadOrCreate`.

- [ ] **Step 3: Implement `internal/server/keys/keys.go`**

```go
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
		return x509.ParseECPrivateKey(block.Bytes)
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
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/server/keys/ -v && go vet ./internal/server/keys/`
Expected: PASS; vet clean.

- [ ] **Step 5: Commit**

```bash
git add internal/server/keys/
git commit -m "feat(server): load-or-generate ECDSA P-256 server keypair (PEM)"
```

---

## Task 3: Device token sign/verify

**Files:**
- Create: `internal/server/auth/token.go`, `internal/server/auth/token_test.go`

Mirrors `internal/licensing`'s ES256 scheme, simplified to a 2-segment token `base64url(claimsJSON).base64url(r||s)`.

- [ ] **Step 1: Write the failing test (`internal/server/auth/token_test.go`)**

```go
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

	// Tamper the claims segment.
	parts := strings.SplitN(tok, ".", 2)
	if _, err := s.Verify("x" + parts[0][1:] + "." + parts[1]); err == nil {
		t.Error("expected tampered token to fail")
	}
	// A different key must not verify.
	other := NewSigner(testKey(t))
	if _, err := other.Verify(tok); err == nil {
		t.Error("expected foreign-key verify to fail")
	}
	// Malformed.
	if _, err := s.Verify("garbage"); err == nil {
		t.Error("expected malformed token to fail")
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `go test ./internal/server/auth/ -run 'TestSignVerify|TestVerifyRejects' -v`
Expected: FAIL — `undefined: NewSigner`.

- [ ] **Step 3: Implement `internal/server/auth/token.go`**

```go
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
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/server/auth/ -run 'TestSignVerify|TestVerifyRejects' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/auth/token.go internal/server/auth/token_test.go
git commit -m "feat(server): ECDSA device bearer-token sign/verify"
```

---

## Task 4: Enrollment orchestration

**Files:**
- Create: `internal/server/auth/enroll.go`, `internal/server/auth/enroll_test.go`

- [ ] **Step 1: Write the failing test (`internal/server/auth/enroll_test.go`)**

```go
package auth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/server/store"
)

func TestEnrollIssuesVerifiableToken(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Unix(1_700_000_000, 0).UTC()
	org, _ := st.CreateOrg("Acme")

	raw := "secret-enroll-token"
	_ = st.CreateEnrollmentToken(HashToken(raw), org.ID, now.Add(time.Hour), 1, now)

	signer := NewSigner(testKey(t))
	res, err := Enroll(st, signer, EnrollInput{EnrollmentToken: raw, DeviceName: "laptop", Platform: "darwin"}, now)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.OrgID != org.ID || res.DeviceID == "" || res.Token == "" {
		t.Fatalf("result = %+v", res)
	}
	claims, err := signer.Verify(res.Token)
	if err != nil || claims.DeviceID != res.DeviceID || claims.OrgID != org.ID {
		t.Fatalf("token claims = %+v err=%v", claims, err)
	}
	// Reuse beyond max_uses=1 fails.
	if _, err := Enroll(st, signer, EnrollInput{EnrollmentToken: raw, DeviceName: "x", Platform: "darwin"}, now); err != store.ErrEnrollment {
		t.Errorf("second enroll err = %v, want ErrEnrollment", err)
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `go test ./internal/server/auth/ -run TestEnrollIssues -v`
Expected: FAIL — `undefined: HashToken` / `Enroll`.

- [ ] **Step 3: Implement `internal/server/auth/enroll.go`**

```go
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/redactrai/redactr/internal/server/store"
)

// HashToken returns the hex SHA-256 of a raw enrollment token (what the DB stores).
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

type EnrollInput struct {
	EnrollmentToken string
	DeviceName      string
	Platform        string
}

type EnrollResult struct {
	DeviceID string
	OrgID    string
	Token    string
}

// Enroll validates the enrollment token (via the store's transactional check),
// creates the device, and issues a signed device bearer token.
func Enroll(st *store.Store, signer *Signer, in EnrollInput, now time.Time) (EnrollResult, error) {
	dev, err := st.EnrollDevice(HashToken(in.EnrollmentToken), in.DeviceName, in.Platform, now)
	if err != nil {
		return EnrollResult{}, err // store.ErrEnrollment on invalid token
	}
	tok, err := signer.Sign(Claims{DeviceID: dev.ID, OrgID: dev.OrgID, IssuedAt: now.Unix()})
	if err != nil {
		return EnrollResult{}, err
	}
	return EnrollResult{DeviceID: dev.ID, OrgID: dev.OrgID, Token: tok}, nil
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/server/auth/ -v`
Expected: PASS (token + enroll tests).

- [ ] **Step 5: Commit**

```bash
git add internal/server/auth/enroll.go internal/server/auth/enroll_test.go
git commit -m "feat(server): device enrollment orchestration (hash, store, issue token)"
```

---

## Task 5: Auth middleware (RequireDevice, RequireAdmin, context)

**Files:**
- Create: `internal/server/auth/middleware.go`, `internal/server/auth/middleware_test.go`

- [ ] **Step 1: Write the failing test (`internal/server/auth/middleware_test.go`)**

```go
package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/server/store"
)

func TestRequireDevice(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "m.db"))
	defer st.Close()
	now := time.Unix(1_700_000_000, 0).UTC()
	org, _ := st.CreateOrg("Acme")
	_ = st.CreateEnrollmentToken(HashToken("tok"), org.ID, now.Add(time.Hour), 0, now)
	signer := NewSigner(testKey(t))
	res, _ := Enroll(st, signer, EnrollInput{EnrollmentToken: "tok", DeviceName: "d", Platform: "darwin"}, now)

	var gotOrg, gotDev string
	h := RequireDevice(st, signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg, gotDev = OrgID(r.Context()), DeviceID(r.Context())
		w.WriteHeader(200)
	}))

	// Valid bearer → 200 + context populated.
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+res.Token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || gotOrg != org.ID || gotDev != res.DeviceID {
		t.Fatalf("code=%d org=%q dev=%q", rec.Code, gotOrg, gotDev)
	}

	// Missing header → 401.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 401 {
		t.Errorf("missing-auth code = %d, want 401", rec.Code)
	}

	// Revoked device → 401.
	_ = st.RevokeDevice(res.DeviceID)
	req2 := httptest.NewRequest("GET", "/x", nil)
	req2.Header.Set("Authorization", "Bearer "+res.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req2)
	if rec.Code != 401 {
		t.Errorf("revoked code = %d, want 401", rec.Code)
	}
}

func TestRequireAdmin(t *testing.T) {
	h := RequireAdmin("sekret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/x", nil)
	req.Header.Set("X-Admin-Key", "sekret")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("good key code = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/x", nil))
	if rec.Code != 401 {
		t.Errorf("missing key code = %d, want 401", rec.Code)
	}
}
```

- [ ] **Step 2: Run to verify fail**

Run: `go test ./internal/server/auth/ -run 'TestRequireDevice|TestRequireAdmin' -v`
Expected: FAIL — `undefined: RequireDevice`.

- [ ] **Step 3: Implement `internal/server/auth/middleware.go`**

```go
package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/redactrai/redactr/internal/server/store"
)

type ctxKey int

const (
	ctxOrgID ctxKey = iota
	ctxDeviceID
)

// OrgID / DeviceID read the authenticated identity from the request context.
func OrgID(ctx context.Context) string    { v, _ := ctx.Value(ctxOrgID).(string); return v }
func DeviceID(ctx context.Context) string { v, _ := ctx.Value(ctxDeviceID).(string); return v }

// RequireDevice authenticates a device bearer token and injects org/device IDs.
func RequireDevice(st *store.Store, signer *Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if raw == "" || raw == r.Header.Get("Authorization") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			claims, err := signer.Verify(raw)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			dev, err := st.GetDevice(claims.DeviceID)
			if err != nil || dev.Revoked || dev.OrgID != claims.OrgID {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = st.TouchDevice(dev.ID, time.Now().UTC()) // best-effort
			ctx := context.WithValue(r.Context(), ctxOrgID, dev.OrgID)
			ctx = context.WithValue(ctx, ctxDeviceID, dev.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin gates a handler behind the X-Admin-Key header (constant-time compare).
func RequireAdmin(adminKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := r.Header.Get("X-Admin-Key")
			if adminKey == "" || subtle.ConstantTimeCompare([]byte(got), []byte(adminKey)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/server/auth/ -v && go vet ./internal/server/auth/`
Expected: all auth tests PASS; vet clean.

- [ ] **Step 5: Commit**

```bash
git add internal/server/auth/middleware.go internal/server/auth/middleware_test.go
git commit -m "feat(server): RequireDevice + RequireAdmin auth middleware"
```

---

## Task 6: HTTP API + `cmd/redactr-server` + end-to-end test

**Files:**
- Create: `internal/server/httpapi/server.go`, `internal/server/httpapi/server_test.go`, `cmd/redactr-server/main.go`

- [ ] **Step 1: Write the failing end-to-end test (`internal/server/httpapi/server_test.go`)**

```go
package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/redactrai/redactr/internal/server/auth"
	"github.com/redactrai/redactr/internal/server/store"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := New(st, auth.NewSigner(priv), "admin-key")
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

func postJSON(t *testing.T, ts *httptest.Server, path, adminKey string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
	if adminKey != "" {
		req.Header.Set("X-Admin-Key", adminKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestEnrollWhoamiRevokeFlow(t *testing.T) {
	ts := newTestServer(t)

	// Create org.
	resp := postJSON(t, ts, "/admin/orgs", "admin-key", map[string]string{"name": "Acme"})
	var org struct{ ID string `json:"id"` }
	json.NewDecoder(resp.Body).Decode(&org)
	resp.Body.Close()
	if org.ID == "" {
		t.Fatal("no org id")
	}

	// Mint enrollment token.
	resp = postJSON(t, ts, "/admin/orgs/"+org.ID+"/enrollment-tokens", "admin-key",
		map[string]int{"expires_in_hours": 1, "max_uses": 1})
	var mint struct{ Token string `json:"token"` }
	json.NewDecoder(resp.Body).Decode(&mint)
	resp.Body.Close()
	if mint.Token == "" {
		t.Fatal("no enrollment token")
	}

	// Enroll (public, no admin key).
	resp = postJSON(t, ts, "/v1/enroll", "",
		map[string]string{"enrollment_token": mint.Token, "device_name": "laptop", "platform": "darwin"})
	var enr struct{ DeviceID, Token string }
	var enrRaw map[string]string
	json.NewDecoder(resp.Body).Decode(&enrRaw)
	resp.Body.Close()
	enr.DeviceID, enr.Token = enrRaw["device_id"], enrRaw["token"]
	if resp.StatusCode != 200 || enr.Token == "" {
		t.Fatalf("enroll code=%d body=%v", resp.StatusCode, enrRaw)
	}

	// whoami with bearer → 200.
	req, _ := http.NewRequest("GET", ts.URL+"/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+enr.Token)
	who, _ := http.DefaultClient.Do(req)
	if who.StatusCode != 200 {
		t.Fatalf("whoami code = %d, want 200", who.StatusCode)
	}
	who.Body.Close()

	// Revoke device → whoami now 401.
	rv := postJSON(t, ts, "/admin/devices/"+enr.DeviceID+"/revoke", "admin-key", nil)
	rv.Body.Close()
	req2, _ := http.NewRequest("GET", ts.URL+"/v1/whoami", nil)
	req2.Header.Set("Authorization", "Bearer "+enr.Token)
	who2, _ := http.DefaultClient.Do(req2)
	if who2.StatusCode != 401 {
		t.Fatalf("post-revoke whoami code = %d, want 401", who2.StatusCode)
	}
	who2.Body.Close()
}

func TestAdminKeyRequired(t *testing.T) {
	ts := newTestServer(t)
	resp := postJSON(t, ts, "/admin/orgs", "", map[string]string{"name": "X"}) // no key
	if resp.StatusCode != 401 {
		t.Errorf("no-admin-key code = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}
```

- [ ] **Step 2: Run to verify fail**

Run: `go test ./internal/server/httpapi/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Implement `internal/server/httpapi/server.go`**

```go
// Package httpapi wires the control-plane server's HTTP routes.
package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/redactrai/redactr/internal/server/auth"
	"github.com/redactrai/redactr/internal/server/store"
)

type Server struct {
	store    *store.Store
	signer   *auth.Signer
	adminKey string
	mux      *http.ServeMux
}

// New builds the control-plane HTTP handler.
func New(st *store.Store, signer *auth.Signer, adminKey string) *Server {
	s := &Server{store: st, signer: signer, adminKey: adminKey, mux: http.NewServeMux()}
	dev := auth.RequireDevice(st, signer)
	admin := auth.RequireAdmin(adminKey)

	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	s.mux.Handle("GET /v1/whoami", dev(http.HandlerFunc(s.handleWhoami)))
	// SEAM A2: s.mux.Handle("GET /v1/policy", dev(http.HandlerFunc(s.handlePolicy)))
	// SEAM A4: s.mux.Handle("POST /v1/events", dev(http.HandlerFunc(s.handleEvents)))

	s.mux.Handle("POST /admin/orgs", admin(http.HandlerFunc(s.handleCreateOrg)))
	s.mux.Handle("GET /admin/orgs", admin(http.HandlerFunc(s.handleListOrgs)))
	s.mux.Handle("POST /admin/orgs/{id}/enrollment-tokens", admin(http.HandlerFunc(s.handleMintToken)))
	s.mux.Handle("GET /admin/devices", admin(http.HandlerFunc(s.handleListDevices)))
	s.mux.Handle("POST /admin/devices/{id}/revoke", admin(http.HandlerFunc(s.handleRevokeDevice)))
	// SEAM A5: the dashboard UI wraps these admin routes; richer admin auth replaces the single key.
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		EnrollmentToken string `json:"enrollment_token"`
		DeviceName      string `json:"device_name"`
		Platform        string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, err := auth.Enroll(s.store, s.signer,
		auth.EnrollInput{EnrollmentToken: in.EnrollmentToken, DeviceName: in.DeviceName, Platform: in.Platform},
		time.Now().UTC())
	if err != nil {
		http.Error(w, "enrollment failed", http.StatusUnauthorized)
		return
	}
	writeJSON(w, 200, map[string]string{"device_id": res.DeviceID, "org_id": res.OrgID, "token": res.Token})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{
		"device_id": auth.DeviceID(r.Context()),
		"org_id":    auth.OrgID(r.Context()),
	})
}

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name string `json:"name"` }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	org, err := s.store.CreateOrg(in.Name)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]string{"id": org.ID, "name": org.Name})
}

func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrgs()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, orgs)
}

func (s *Server) handleMintToken(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if _, err := s.store.GetOrg(orgID); err != nil {
		http.Error(w, "unknown org", http.StatusNotFound)
		return
	}
	var in struct {
		ExpiresInHours int `json:"expires_in_hours"`
		MaxUses        int `json:"max_uses"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if in.ExpiresInHours <= 0 {
		in.ExpiresInHours = 24
	}
	now := time.Now().UTC()
	rawToken := newRawToken() // shown to the admin once; only its hash is stored
	expires := now.Add(time.Duration(in.ExpiresInHours) * time.Hour)
	if err := s.store.CreateEnrollmentToken(auth.HashToken(rawToken), orgID, expires, in.MaxUses, now); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]any{"token": rawToken, "expires_at": expires})
}

func newRawToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.store.ListDevices(r.URL.Query().Get("org"))
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, devs)
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeDevice(r.PathValue("id")); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]bool{"revoked": true})
}
```

> NOTE for the implementer: `httpapi/server.go` needs imports `crypto/rand` and `encoding/base64` (used by `newRawToken`) in addition to `encoding/json`/`net/http`/`time` and the two internal packages.

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/server/httpapi/ -v`
Expected: `TestEnrollWhoamiRevokeFlow` + `TestAdminKeyRequired` PASS.

- [ ] **Step 5: Implement `cmd/redactr-server/main.go`**

```go
// Command redactr-server is the Redactr v2 control-plane server.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redactrai/redactr/internal/server/auth"
	"github.com/redactrai/redactr/internal/server/httpapi"
	"github.com/redactrai/redactr/internal/server/keys"
	"github.com/redactrai/redactr/internal/server/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("REDACTR_SERVER_ADDR", ":8080")
	dbPath := env("REDACTR_SERVER_DB", "./redactr-server.db")
	keyDir := env("REDACTR_SERVER_KEY_DIR", "./keys")

	adminKey := os.Getenv("REDACTR_ADMIN_KEY")
	if adminKey == "" {
		var b [24]byte
		_, _ = rand.Read(b[:])
		adminKey = base64.RawURLEncoding.EncodeToString(b[:])
		slog.Warn("no REDACTR_ADMIN_KEY set — generated one (set it to persist across restarts)", "admin_key", adminKey)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	priv, err := keys.LoadOrCreate(keyDir)
	if err != nil {
		log.Fatalf("keys: %v", err)
	}

	srv := &http.Server{Addr: addr, Handler: httpapi.New(st, auth.NewSigner(priv), adminKey)}

	go func() {
		slog.Info("redactr-server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
```

- [ ] **Step 6: Verify everything**

Run:
```bash
go build ./...
go test ./internal/server/... -v
go test ./internal/... 2>&1 | grep -v "no test files"
go vet ./...
CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/ ./internal/server/...
CGO_ENABLED=0 GOOS=windows go build ./cmd/redactr-server/ ./internal/server/...
gofmt -l internal/server/ cmd/redactr-server/
```
Expected: all build/test/vet PASS; both cross-compiles succeed; gofmt clean.

- [ ] **Step 7: Commit**

```bash
git add internal/server/httpapi/ cmd/redactr-server/
git commit -m "feat(server): control-plane HTTP API + redactr-server binary (enroll/whoami/admin)"
```

---

## Final verification

- [ ] Run the full bar:
```bash
go build ./... && go test ./internal/... 2>&1 | grep -v "no test files" && go vet ./... \
  && CGO_ENABLED=0 GOOS=linux go build ./cmd/redactr-server/ ./internal/server/... \
  && CGO_ENABLED=0 GOOS=windows go build ./cmd/redactr-server/ ./internal/server/...
```
Expected: all green; both cross-compiles succeed.

---

## Self-Review notes (coverage map)

- **Store + schema + transactional enroll** → Task 1.
- **ECDSA keypair load/generate** → Task 2.
- **Device token sign/verify (+ tamper/foreign-key)** → Task 3.
- **Enrollment orchestration (+ max-uses)** → Task 4.
- **RequireDevice + RequireAdmin + context** → Task 5.
- **HTTP API + binary + end-to-end mint→enroll→whoami→revoke→401** → Task 6.
- **SEAMs** for A2 (`/v1/policy`), A4 (`/v1/events`), A5 (dashboard/admin-auth), A3 (image pipeline) → noted in `httpapi/server.go`.
- **Pure-Go / cross-compile** → modernc sqlite; verified by GOOS=linux/windows builds.
