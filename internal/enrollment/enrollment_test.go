package enrollment

import (
	"testing"
)

func TestSaveLoadExists(t *testing.T) {
	base := t.TempDir()
	if Exists(base) {
		t.Fatal("should not exist yet")
	}
	e := Enrollment{ServerURL: "https://s", DeviceToken: "tok", ServerPublicKey: "PEM", DeviceID: "d", OrgID: "o"}
	if err := Save(base, e); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !Exists(base) {
		t.Fatal("should exist after Save")
	}
	got, err := Load(base)
	if err != nil || got.ServerURL != "https://s" || got.DeviceToken != "tok" || got.OrgID != "o" {
		t.Fatalf("Load = %+v err=%v", got, err)
	}
}
