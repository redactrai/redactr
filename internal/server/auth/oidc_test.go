package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

const testKID = "test-key-1"

// mustRandString returns a random URL-safe base64 string (16 bytes) or panics.
// It delegates to the production randB64 to avoid duplicating the logic.
func mustRandString() string {
	s, err := randB64(16)
	if err != nil {
		panic(err)
	}
	return s
}

// mockIDP is a fake OpenID Connect provider backed by an httptest.Server.
type mockIDP struct {
	URL  string
	priv *rsa.PrivateKey
	// clientID is the expected audience for issued ID tokens.
	clientID string
	// codes maps a one-time auth code to the token claims it should mint.
	codes           map[string]codeBinding
	defaultEmail    string
	defaultVerified bool
	// omitIDToken, when true, causes /token to return no id_token field.
	omitIDToken bool
}

type codeBinding struct {
	email         string
	emailVerified bool
	nonce         string
	// challenge is the S256 PKCE challenge that must match the presented
	// code_verifier at token exchange time. Empty means "skip PKCE check"
	// (should only be used for tests that exercise non-PKCE paths).
	challenge string
}

// Code registers a one-time auth code bound to (defaultEmail, defaultVerified,
// nonce, challenge) and returns the code. challenge should be
// oauth2.S256ChallengeFromVerifier(verifier) so the mock can verify PKCE.
func (m *mockIDP) Code(nonce, challenge string) string {
	return m.codeWith(m.defaultEmail, m.defaultVerified, nonce, challenge)
}

// codeWith lets a test bind an explicit email/verified/nonce/challenge to a
// fresh code.
func (m *mockIDP) codeWith(email string, verified bool, nonce, challenge string) string {
	code := mustRandString()
	m.codes[code] = codeBinding{
		email:         email,
		emailVerified: verified,
		nonce:         nonce,
		challenge:     challenge,
	}
	return code
}

func newMockIDP(t *testing.T, email string, emailVerified bool) *mockIDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	m := &mockIDP{
		priv:            priv,
		clientID:        "cid",
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

		// PKCE verification: if the binding carries a challenge, validate that
		// the presented code_verifier hashes to it. Reject if verifier absent.
		verifier := r.FormValue("code_verifier")
		if cb.challenge != "" {
			if verifier == "" {
				http.Error(w, "missing code_verifier", http.StatusBadRequest)
				return
			}
			if oauth2.S256ChallengeFromVerifier(verifier) != cb.challenge {
				http.Error(w, "pkce mismatch", http.StatusBadRequest)
				return
			}
		}

		if m.omitIDToken {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "at",
				"token_type":   "Bearer",
			})
			return
		}

		idToken, err := m.signIDToken(base, m.clientID, cb)
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
	code := idp.Code(st.Nonce, oauth2.S256ChallengeFromVerifier(st.Verifier))
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
	if _, err := p.Exchange(ctx, "anycode", "wrong", st); !errors.Is(err, ErrState) {
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
	code := idp.Code(st.Nonce, oauth2.S256ChallengeFromVerifier(st.Verifier))
	if _, err := p.Exchange(ctx, code, st.State, st); !errors.Is(err, ErrEmailUnverified) {
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
	code := idp.codeWith("alice@x.com", true, "a-different-nonce", oauth2.S256ChallengeFromVerifier(st.Verifier))
	if _, err := p.Exchange(ctx, code, st.State, st); !errors.Is(err, ErrNonce) {
		t.Fatalf("err = %v, want ErrNonce", err)
	}
}

// TestOIDCTokenRequestSendsPKCEVerifier confirms that Exchange sends a
// non-empty code_verifier and that the mock enforces the S256 round-trip.
// A wrong verifier must cause the exchange to fail (not return valid claims).
func TestOIDCTokenRequestSendsPKCEVerifier(t *testing.T) {
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

	// Bind the code to the CORRECT challenge so the mock enforces PKCE.
	// Then tamper: create a second AuthState with a different verifier so the
	// verifier sent by Exchange won't match the stored challenge.
	correctChallenge := oauth2.S256ChallengeFromVerifier(st.Verifier)
	code := idp.Code(st.Nonce, correctChallenge)

	// Build a tampered state that has a different verifier but same state/nonce.
	wrongVerifier := oauth2.GenerateVerifier()
	tamperedSt := AuthState{
		State:    st.State,
		Nonce:    st.Nonce,
		Verifier: wrongVerifier,
	}

	if _, err := p.Exchange(ctx, code, tamperedSt.State, tamperedSt); err == nil {
		t.Fatal("Exchange with wrong code_verifier should have failed, got nil error")
	}
}

// TestOIDCRejectsMissingIDToken confirms that a token response lacking an
// id_token is rejected with ErrNoIDToken.
func TestOIDCRejectsMissingIDToken(t *testing.T) {
	ctx := context.Background()
	idp := newMockIDP(t, "alice@x.com", true)
	idp.omitIDToken = true

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
	// omitIDToken mode: challenge field empty so mock skips PKCE check,
	// allowing us to isolate the missing-id_token path.
	code := idp.Code(st.Nonce, "")
	if _, err := p.Exchange(ctx, code, st.State, st); !errors.Is(err, ErrNoIDToken) {
		t.Fatalf("err = %v, want ErrNoIDToken", err)
	}
}
