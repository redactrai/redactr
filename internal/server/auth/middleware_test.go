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
