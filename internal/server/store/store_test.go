package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redactrai/redactr/internal/control"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOrgAndTokenAndDeviceCRUD(t *testing.T) {
	s := openTest(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	org, err := s.CreateOrg("Acme")
	if err != nil || org.ID == "" || org.Name != "Acme" {
		t.Fatalf("CreateOrg: %+v err=%v", org, err)
	}
	orgs, err := s.ListOrgs()
	if err != nil || len(orgs) != 1 {
		t.Fatalf("ListOrgs: %v len=%d", err, len(orgs))
	}

	if err := s.CreateEnrollmentToken("HASH1", org.ID, now.Add(time.Hour), 2, now); err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	d1, err := s.EnrollDevice("HASH1", "laptop", "darwin", now)
	if err != nil || d1.ID == "" || d1.OrgID != org.ID {
		t.Fatalf("EnrollDevice#1: %+v err=%v", d1, err)
	}
	d2, err := s.EnrollDevice("HASH1", "laptop2", "windows", now)
	if err != nil {
		t.Fatalf("EnrollDevice#2: %v", err)
	}
	if _, err := s.EnrollDevice("HASH1", "laptop3", "linux", now); err != ErrEnrollment {
		t.Fatalf("EnrollDevice#3 err = %v, want ErrEnrollment", err)
	}

	got, err := s.GetDevice(d1.ID)
	if err != nil || got.Revoked {
		t.Fatalf("GetDevice: %+v err=%v", got, err)
	}
	if err := s.RevokeDevice(d1.ID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	got, _ = s.GetDevice(d1.ID)
	if !got.Revoked {
		t.Errorf("device should be revoked")
	}
	devs, err := s.ListDevices(org.ID)
	if err != nil || len(devs) != 2 {
		t.Fatalf("ListDevices: %v len=%d", err, len(devs))
	}
	_ = d2
}

func TestEnrollExpiredAndRevokedToken(t *testing.T) {
	s := openTest(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	org, _ := s.CreateOrg("Acme")

	_ = s.CreateEnrollmentToken("EXP", org.ID, now.Add(-time.Hour), 0, now)
	if _, err := s.EnrollDevice("EXP", "d", "darwin", now); err != ErrEnrollment {
		t.Errorf("expired token err = %v, want ErrEnrollment", err)
	}
	if _, err := s.EnrollDevice("NOPE", "d", "darwin", now); err != ErrEnrollment {
		t.Errorf("unknown token err = %v, want ErrEnrollment", err)
	}
}

func TestEnrollRevokedToken(t *testing.T) {
	s := openTest(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	org, _ := s.CreateOrg("Acme")
	_ = s.CreateEnrollmentToken("REV", org.ID, now.Add(time.Hour), 0, now)
	if err := s.RevokeToken("REV"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := s.EnrollDevice("REV", "d", "darwin", now); err != ErrEnrollment {
		t.Errorf("revoked-token enroll err = %v, want ErrEnrollment", err)
	}
}

func TestPolicyGetSeedAndPut(t *testing.T) {
	s := openTest(t)
	org, _ := s.CreateOrg("Acme")

	raw, ver, err := s.GetPolicy(org.ID)
	if err != nil || ver != 0 {
		t.Fatalf("GetPolicy seed: ver=%d err=%v", ver, err)
	}
	if !strings.Contains(string(raw), "redactr-base:local") {
		t.Errorf("seed bundle = %s", raw)
	}

	v1, err := s.PutPolicy(org.ID, []byte(`{"image":"redactr-base:v2","mountMode":"bind","denylist":["evil.test"]}`))
	if err != nil || v1 != 1 {
		t.Fatalf("PutPolicy#1: v=%d err=%v", v1, err)
	}
	v2, _ := s.PutPolicy(org.ID, []byte(`{"image":"redactr-base:v3","mountMode":"bind","denylist":[]}`))
	if v2 != 2 {
		t.Errorf("PutPolicy#2 v=%d want 2", v2)
	}
	raw, ver, _ = s.GetPolicy(org.ID)
	if ver != 2 || !strings.Contains(string(raw), "redactr-base:v3") {
		t.Errorf("GetPolicy after put: ver=%d raw=%s", ver, raw)
	}
}

func TestEventsInsertListCount(t *testing.T) {
	s := openTest(t)
	org, _ := s.CreateOrg("Acme")
	now := time.Unix(1_700_000_000, 0).UTC()
	evs := []control.MonitorEvent{
		{Tool: "Claude Code", Verdict: "runaway", Reason: "direct", DirectConnCount: 1, ObservedAt: now},
		{Tool: "Codex", Verdict: "protected", Reason: "via proxy", DirectConnCount: 0, ObservedAt: now},
	}
	if err := s.InsertEvents(org.ID, "dev1", evs, now); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}
	got, err := s.ListEvents(org.ID, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("ListEvents: %v len=%d", err, len(got))
	}
	if got[0].DeviceID != "dev1" || got[0].OrgID != org.ID {
		t.Errorf("event missing ids: %+v", got[0])
	}
	counts, err := s.CountByVerdict(org.ID, now.Add(-time.Hour))
	if err != nil || counts["runaway"] != 1 || counts["protected"] != 1 {
		t.Fatalf("CountByVerdict: %v %+v", err, counts)
	}
}

func TestListEventsEmptyIsNonNil(t *testing.T) {
	s := openTest(t)
	org, _ := s.CreateOrg("Empty")
	got, err := s.ListEvents(org.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("ListEvents should return a non-nil empty slice")
	}
}

func TestImagesLifecycle(t *testing.T) {
	s := openTest(t)
	org, _ := s.CreateOrg("Acme")
	id, err := s.InsertImage(org.ID, "team-tools")
	if err != nil || id == "" {
		t.Fatalf("InsertImage: %v id=%q", err, id)
	}
	imgs, _ := s.ListImages(org.ID)
	if len(imgs) != 1 || imgs[0].Status != "building" || imgs[0].Tag != "team-tools" {
		t.Fatalf("ListImages: %+v", imgs)
	}
	if err := s.SetImageResult(id, "reg/acme/team-tools", "sha256:abc", "ready"); err != nil {
		t.Fatalf("SetImageResult: %v", err)
	}
	imgs, _ = s.ListImages(org.ID)
	if imgs[0].Status != "ready" || imgs[0].Digest != "sha256:abc" || imgs[0].Ref != "reg/acme/team-tools" {
		t.Errorf("after SetImageResult: %+v", imgs[0])
	}
}
