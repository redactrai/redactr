package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/redactrai/redactr/internal/server/auth"
)

// oidcStateCookie is the short-lived cookie that carries the OIDC AuthState
// (state/nonce/PKCE verifier) between /admin/oidc/start and /admin/oidc/callback.
const oidcStateCookie = "redactr_oidc"

// handleLoginForm renders a minimal self-contained login form. When SSO is
// configured it also offers a "Sign in with SSO" link to /admin/oidc/start.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var sso string
	if s.oidc != nil {
		sso = `<p><a href="/admin/oidc/start">Sign in with SSO</a></p>`
	}
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Redactr Admin Login</title></head>
<body>
<h1>Redactr Admin</h1>
<form method="post" action="/admin/login">
  <p><label>Username <input type="text" name="username" autocomplete="username"></label></p>
  <p><label>Password <input type="password" name="password" autocomplete="current-password"></label></p>
  <p><button type="submit">Sign in</button></p>
</form>` + sso + `
</body></html>`))
}

// handleLogin verifies the super-admin credentials and, on success, creates a
// superadmin session, sets the session cookie, and redirects to /.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SuperadminHash == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	user := r.PostFormValue("username")
	pass := r.PostFormValue("password")
	if !auth.VerifySuperadmin(user, pass, s.cfg.SuperadminUser, s.cfg.SuperadminHash) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sess, err := s.store.CreateSession(user, "superadmin", s.cfg.SessionTTL)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, sess.ID, s.cfg.Secure, s.cfg.SessionTTL)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLogout deletes the current session (best-effort), clears the cookie,
// and redirects to the login form.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookieName); err == nil {
		_ = s.store.DeleteSession(c.Value)
	}
	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// handleOIDCStart begins the SSO login flow: it generates state/nonce/PKCE,
// stashes them in a short-lived cookie, and redirects to the IdP.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	authURL, asState, err := s.oidc.Start()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	raw, err := json.Marshal(asState)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    string(raw),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback completes the SSO flow: it validates the code/state against
// the stashed AuthState, requires the verified email to be an authorized admin,
// then creates an admin session.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	c, err := r.Cookie(oidcStateCookie)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Clear the state cookie regardless of outcome (single use).
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	var asState auth.AuthState
	if err := json.Unmarshal([]byte(c.Value), &asState); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	claims, err := s.oidc.Exchange(r.Context(), r.URL.Query().Get("code"), r.URL.Query().Get("state"), asState)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ok, _ := s.store.IsAdmin(claims.Email)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sess, err := s.store.CreateSession(claims.Email, "admin", s.cfg.SessionTTL)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, sess.ID, s.cfg.Secure, s.cfg.SessionTTL)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleMe returns the identity of the current session (admin or superadmin).
// The SPA calls this on load to populate the "whoami" label and to confirm the
// session cookie is still valid (a 401 redirects the browser to /admin/login).
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"subject": auth.SessionSubject(r.Context()),
		"role":    auth.SessionRole(r.Context()),
	})
}

// handleListAdmins returns the admin allowlist (superadmin only).
func (s *Server) handleListAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := s.store.ListAdmins()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if admins == nil {
		admins = []string{}
	}
	writeJSON(w, http.StatusOK, admins)
}

// handleAddAdmin adds an email to the admin allowlist (superadmin only).
func (s *Server) handleAddAdmin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if in.Email == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.store.AddAdmin(in.Email, auth.SessionSubject(r.Context())); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"email": in.Email})
}

// handleDeleteAdmin removes an email from the admin allowlist (superadmin only).
func (s *Server) handleDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RemoveAdmin(r.PathValue("email")); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
