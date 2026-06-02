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
			authz := r.Header.Get("Authorization")
			raw := strings.TrimPrefix(authz, "Bearer ")
			if raw == "" || raw == authz {
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
