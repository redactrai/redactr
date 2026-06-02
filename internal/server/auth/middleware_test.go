package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rakeshguha/redactr/internal/server/store"
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

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+res.Token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || gotOrg != org.ID || gotDev != res.DeviceID {
		t.Fatalf("code=%d org=%q dev=%q", rec.Code, gotOrg, gotDev)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 401 {
		t.Errorf("missing-auth code = %d, want 401", rec.Code)
	}

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

func TestRequireAdminEmptyKeyFailsClosed(t *testing.T) {
	h := RequireAdmin("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	// Even presenting an empty key must be rejected.
	req := httptest.NewRequest("POST", "/admin/x", nil)
	req.Header.Set("X-Admin-Key", "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("empty configured admin key code = %d, want 401", rec.Code)
	}
}
