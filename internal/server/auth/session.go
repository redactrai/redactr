package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/redactrai/redactr/internal/server/store"
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

// SessionCookieName is the name of the HTTP cookie that carries the admin session ID.
const SessionCookieName = "redactr_admin"

// RequireSession returns middleware that validates the redactr_admin cookie.
// A "superadmin" session satisfies any required role; "admin" only satisfies role=="admin".
// On missing/invalid cookie or lookup error → 401. On insufficient role → 403.
// This middleware never redirects — callers handle redirect logic.
func RequireSession(role string, lookup SessionLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				// http.ErrNoCookie or missing
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			sess, err := lookup(cookie.Value)
			if err != nil {
				if !errors.Is(err, store.ErrSessionNotFound) && !errors.Is(err, store.ErrSessionExpired) {
					slog.Error("session lookup failed", "err", err)
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
// maxAge should match the server-side session TTL so the browser drops the
// cookie when the session expires.
func SetSessionCookie(w http.ResponseWriter, id string, secure bool, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})
}

// ClearSessionCookie expires the redactr_admin cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// VerifySuperadmin returns true if gotUser matches wantUser and gotPass matches
// bcryptHash. Both checks always run — bcrypt.CompareHashAndPassword is never
// short-circuited — so response time does not reveal whether the username is
// valid. Production hashes must use bcrypt cost >= 12.
func VerifySuperadmin(gotUser, gotPass, wantUser, bcryptHash string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser)) // 1 if equal
	passOK := 0
	if bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(gotPass)) == nil {
		passOK = 1
	}
	return subtle.ConstantTimeEq(int32(userOK+passOK), 2) == 1
}
