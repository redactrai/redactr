package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testKID = "test-key-1"

// mockIDP is a fake OpenID Connect provider backed by an httptest.Server.
type mockIDP struct {
	URL  string
	priv *rsa.PrivateKey
	// codes maps a one-time auth code to the token claims it should mint.
	codes           map[string]codeBinding
	defaultEmail    string
	defaultVerified bool
}

type codeBinding struct {
	email         string
	emailVerified bool
	nonce         string
}

// Code registers a one-time auth code bound to (email, emailVerified, nonce)
// and returns the code.
func (m *mockIDP) Code(nonce string) string {
	return m.codeWith(m.defaultEmail, m.defaultVerified, nonce)
}

// codeWith lets a test bind an explicit email/verified/nonce to a fresh code.
func (m *mockIDP) codeWith(email string, verified bool, nonce string) string {
	code := randString()
	m.codes[code] = codeBinding{email: email, emailVerified: verified, nonce: nonce}
	return code
}

func randString() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexd[v>>4]
		out[i*2+1] = hexd[v&0x0f]
	}
	return string(out)
}

func newMockIDP(t *testing.T, email string, emailVerified bool) *mockIDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	m := &mockIDP{
		priv:            priv,
		codes:           map[string]codeBinding{},
		defaultEmail:    email,
		defaultVerified: emailVerified,
	}

	mux := http.NewServeMux()
	// base is filled in after the server starts so issuer matches exactly.
	var base string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/auth",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks",
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       &priv.PublicKey,
			KeyID:     testKID,
			Algorithm: "RS256",
			Use:       "sig",
		}
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		cb, ok := m.codes[code]
		if !ok {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		delete(m.codes, code) // one-time use

		idToken, err := m.signIDToken(base, "cid", cb)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "at",
			"token_type":   "Bearer",
			"id_token":     idToken,
		})
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	base = ts.URL
	m.URL = ts.URL
	return m
}

func (m *mockIDP) signIDToken(issuer, clientID string, cb codeBinding) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKID),
	)
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := map[string]any{
		"iss":            issuer,
		"aud":            clientID,
		"sub":            "user-sub",
		"email":          cb.email,
		"email_verified": cb.emailVerified,
		"nonce":          cb.nonce,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func TestOIDCCallbackHappyPath(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t, "Alice@X.com", true)
	p, err := NewOIDC(ctx, OIDCConfig{
		Issuer:       idp.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	_, st, err := p.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	code := idp.Code(st.Nonce)
	claims, err := p.Exchange(ctx, code, st.State, st)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Email != "alice@x.com" {
		t.Errorf("email = %q, want alice@x.com", claims.Email)
	}
	if !claims.EmailVerified {
		t.Errorf("EmailVerified = false, want true")
	}
	if claims.Subject == "" {
		t.Errorf("Subject empty")
	}
}

func TestOIDCRejectsBadState(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t, "alice@x.com", true)
	p, err := NewOIDC(ctx, OIDCConfig{
		Issuer:       idp.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	_, st, err := p.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := p.Exchange(ctx, "anycode", "wrong", st); err != ErrState {
		t.Fatalf("err = %v, want ErrState", err)
	}
}

func TestOIDCRejectsUnverifiedEmail(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t, "alice@x.com", false)
	p, err := NewOIDC(ctx, OIDCConfig{
		Issuer:       idp.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	_, st, err := p.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	code := idp.Code(st.Nonce)
	if _, err := p.Exchange(ctx, code, st.State, st); err != ErrEmailUnverified {
		t.Fatalf("err = %v, want ErrEmailUnverified", err)
	}
}

func TestOIDCRejectsBadNonce(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t, "alice@x.com", true)
	p, err := NewOIDC(ctx, OIDCConfig{
		Issuer:       idp.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		RedirectURL:  "https://app/cb",
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	_, st, err := p.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Mint a token whose embedded nonce differs from st.Nonce.
	code := idp.codeWith("alice@x.com", true, "a-different-nonce")
	if _, err := p.Exchange(ctx, code, st.State, st); err != ErrNonce {
		t.Fatalf("err = %v, want ErrNonce", err)
	}
}
