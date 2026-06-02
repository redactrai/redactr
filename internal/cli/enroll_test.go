package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redactrai/redactr/internal/enrollment"
)

func TestRunEnrollStoresEnrollment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"device_id": "dev1", "org_id": "org1", "token": "bearer-xyz", "server_public_key": "PEMDATA",
		})
	}))
	defer srv.Close()

	base := t.TempDir()
	if err := RunEnroll(base, srv.URL, "enroll-tok"); err != nil {
		t.Fatalf("RunEnroll: %v", err)
	}
	e, err := enrollment.Load(base)
	if err != nil || e.DeviceToken != "bearer-xyz" || e.ServerPublicKey != "PEMDATA" || e.ServerURL != srv.URL || e.OrgID != "org1" {
		t.Fatalf("enrollment = %+v err=%v", e, err)
	}
}
