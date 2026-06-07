package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/redactrai/redactr/internal/server/store"
)

// ctxSession keys for subject and role injected by RequireSession.
const (
	ctxSessionSubject ctxKey = iota + 2
	ctxSessionRole
)

// SessionSubject returns the authenticated subject from the request context.
func SessionSubject(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionSubject).(string)
	return v
}

// SessionRole returns the authenticated role from the request context.
func SessionRole(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionRole).(string)
	return v
}

// SessionLookup is a function that looks up a session by ID.
type SessionLookup func(id string) (store.Session, error)

// RequireSession returns middleware that validates the redactr_admin cookie.
// A "superadmin" session satisfies any required role; "admin" only satisfies role=="admin".
// On missing/invalid cookie or lookup error → 401. On insufficient role → 403.
// This middleware never redirects — callers handle redirect logic.
func RequireSession(role string, lookup SessionLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("redactr_admin")
			if err != nil {
				// http.ErrNoCookie or missing
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			sess, err := lookup(cookie.Value)
			if err != nil {
				if errors.Is(err, store.ErrSessionNotFound) || errors.Is(err, store.ErrSessionExpired) {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Role check: superadmin satisfies any role; admin only satisfies "admin".
			switch sess.Role {
			case "superadmin":
				// satisfies any required role
			case "admin":
				if role != "admin" {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			default:
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), ctxSessionSubject, sess.Subject)
			ctx = context.WithValue(ctx, ctxSessionRole, sess.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SetSessionCookie writes the redactr_admin session cookie.
func SetSessionCookie(w http.ResponseWriter, id string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "redactr_admin",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the redactr_admin cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "redactr_admin",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// VerifySuperadmin returns true if gotUser matches wantUser (constant-time)
// and gotPass matches the bcrypt hash.
func VerifySuperadmin(gotUser, gotPass, wantUser, bcryptHash string) bool {
	userMatch := subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser)) == 1
	passMatch := bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(gotPass)) == nil
	return userMatch && passMatch
}
