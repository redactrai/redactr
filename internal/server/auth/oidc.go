package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrState           = errors.New("oidc: state mismatch")
	ErrNonce           = errors.New("oidc: nonce mismatch")
	ErrEmailUnverified = errors.New("oidc: email not verified")
	ErrNoIDToken       = errors.New("oidc: no id_token in token response")
)

// OIDCConfig is the static configuration for an OIDC relying party.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// OIDCClaims are the verified claims extracted from a validated ID token.
//
// (Named OIDCClaims rather than Claims to avoid colliding with the device
// bearer-token Claims defined in token.go.)
type OIDCClaims struct {
	Email         string
	EmailVerified bool
	Subject       string
}

// OIDC is a configured relying party that can drive the authorization-code +
// PKCE login flow against a discovered provider.
type OIDC struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	conf     oauth2.Config
}

// NewOIDC discovers the provider via its issuer URL and builds the ID-token
// verifier and oauth2 config. The discovery document's issuer must match
// cfg.Issuer exactly (enforced by go-oidc).
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	conf := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}
	return &OIDC{provider: provider, verifier: verifier, conf: conf}, nil
}

// AuthState carries the per-login secrets the caller must persist (in a
// short-lived cookie) between Start and Exchange.
type AuthState struct {
	State    string
	Nonce    string
	Verifier string
}

// Start generates state, nonce, and a PKCE verifier, and returns the IdP
// authorization URL plus the AuthState to stash.
func (o *OIDC) Start() (authURL string, st AuthState, err error) {
	state, err := randB64(16)
	if err != nil {
		return "", AuthState{}, err
	}
	nonce, err := randB64(16)
	if err != nil {
		return "", AuthState{}, err
	}
	verifier := oauth2.GenerateVerifier()
	url := o.conf.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return url, AuthState{State: state, Nonce: nonce, Verifier: verifier}, nil
}

// Exchange validates the returned state, exchanges the code, verifies the ID
// token (signature, aud, iss, exp) and the nonce, requires email_verified, and
// returns the claims. gotState is the state echoed back by the IdP.
func (o *OIDC) Exchange(ctx context.Context, code, gotState string, st AuthState) (OIDCClaims, error) {
	if gotState != st.State {
		return OIDCClaims{}, ErrState
	}
	tok, err := o.conf.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("oidc: code exchange: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return OIDCClaims{}, ErrNoIDToken
	}
	idTok, err := o.verifier.Verify(ctx, rawID)
	if err != nil {
		return OIDCClaims{}, fmt.Errorf("oidc: verify id token: %w", err)
	}
	if idTok.Nonce != st.Nonce {
		return OIDCClaims{}, ErrNonce
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idTok.Claims(&c); err != nil {
		return OIDCClaims{}, fmt.Errorf("oidc: decode claims: %w", err)
	}
	if !c.EmailVerified {
		return OIDCClaims{}, ErrEmailUnverified
	}
	return OIDCClaims{
		Email:         strings.ToLower(c.Email),
		EmailVerified: true,
		Subject:       idTok.Subject,
	}, nil
}

// randB64 returns n random bytes encoded as URL-safe base64 (no padding).
func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
