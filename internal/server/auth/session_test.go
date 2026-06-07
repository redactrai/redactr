package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/redactrai/redactr/internal/server/store"
)

// stubLookup returns a fixed Session or error, keyed by session ID.
type stubLookup struct {
	sessions map[string]store.Session
	err      map[string]error
}

func (sl *stubLookup) lookup(id string) (store.Session, error) {
	if e, ok := sl.err[id]; ok {
		return store.Session{}, e
	}
	if s, ok := sl.sessions[id]; ok {
		return s, nil
	}
	return store.Session{}, store.ErrSessionNotFound
}

func TestRequireSessionAllowsValidRejectsInvalid(t *testing.T) {
	ok200 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	sl := &stubLookup{
		sessions: map[string]store.Session{
			"valid-admin":      {ID: "valid-admin", Subject: "alice@x.com", Role: "admin"},
			"valid-superadmin": {ID: "valid-superadmin", Subject: "super@x.com", Role: "superadmin"},
		},
		err: map[string]error{
			"expired-id": store.ErrSessionExpired,
		},
	}

	// helper: send a request with (optionally) a cookie
	do := func(handler http.Handler, cookieVal string) int {
		req := httptest.NewRequest("GET", "/", nil)
		if cookieVal != "" {
			req.AddCookie(&http.Cookie{Name: "redactr_admin", Value: cookieVal})
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// valid admin cookie → 200
	h := RequireSession("admin", sl.lookup)(ok200)
	if code := do(h, "valid-admin"); code != 200 {
		t.Errorf("valid admin cookie: code=%d want 200", code)
	}

	// missing cookie → 401
	if code := do(h, ""); code != 401 {
		t.Errorf("missing cookie: code=%d want 401", code)
	}

	// lookup returns ErrSessionExpired → 401
	if code := do(h, "expired-id"); code != 401 {
		t.Errorf("expired session: code=%d want 401", code)
	}

	// superadmin session on admin-required route → 200
	if code := do(h, "valid-superadmin"); code != 200 {
		t.Errorf("superadmin on admin route: code=%d want 200", code)
	}

	// admin session on superadmin-required route → 403
	hSuper := RequireSession("superadmin", sl.lookup)(ok200)
	if code := do(hSuper, "valid-admin"); code != 403 {
		t.Errorf("admin on superadmin route: code=%d want 403", code)
	}
}

func TestRequireSessionContextValues(t *testing.T) {
	sl := &stubLookup{
		sessions: map[string]store.Session{
			"s1": {ID: "s1", Subject: "alice@x.com", Role: "admin"},
		},
		err: map[string]error{},
	}

	var gotSubject, gotRole string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSubject = SessionSubject(r.Context())
		gotRole = SessionRole(r.Context())
		w.WriteHeader(200)
	})

	h := RequireSession("admin", sl.lookup)(inner)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "redactr_admin", Value: "s1"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if gotSubject != "alice@x.com" {
		t.Errorf("SessionSubject = %q, want %q", gotSubject, "alice@x.com")
	}
	if gotRole != "admin" {
		t.Errorf("SessionRole = %q, want %q", gotRole, "admin")
	}
}

func TestVerifySuperadmin(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cr3t"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}

	// correct user + pass → true
	if !VerifySuperadmin("admin", "s3cr3t", "admin", string(hash)) {
		t.Error("correct credentials should return true")
	}

	// wrong pass → false
	if VerifySuperadmin("admin", "wrong", "admin", string(hash)) {
		t.Error("wrong password should return false")
	}

	// wrong user → false
	if VerifySuperadmin("other", "s3cr3t", "admin", string(hash)) {
		t.Error("wrong username should return false")
	}
}

// Ensure ErrSessionNotFound/ErrSessionExpired are accessible from auth package.
var _ = errors.Is(store.ErrSessionNotFound, store.ErrSessionNotFound)
var _ = errors.Is(store.ErrSessionExpired, store.ErrSessionExpired)
