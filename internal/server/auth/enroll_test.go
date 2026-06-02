package auth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rakeshguha/redactr/internal/server/store"
)

func TestEnrollIssuesVerifiableToken(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Unix(1_700_000_000, 0).UTC()
	org, _ := st.CreateOrg("Acme")

	raw := "secret-enroll-token"
	_ = st.CreateEnrollmentToken(HashToken(raw), org.ID, now.Add(time.Hour), 1, now)

	signer := NewSigner(testKey(t))
	res, err := Enroll(st, signer, EnrollInput{EnrollmentToken: raw, DeviceName: "laptop", Platform: "darwin"}, now)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.OrgID != org.ID || res.DeviceID == "" || res.Token == "" {
		t.Fatalf("result = %+v", res)
	}
	claims, err := signer.Verify(res.Token)
	if err != nil || claims.DeviceID != res.DeviceID || claims.OrgID != org.ID {
		t.Fatalf("token claims = %+v err=%v", claims, err)
	}
	if _, err := Enroll(st, signer, EnrollInput{EnrollmentToken: raw, DeviceName: "x", Platform: "darwin"}, now); err != store.ErrEnrollment {
		t.Errorf("second enroll err = %v, want ErrEnrollment", err)
	}
}
