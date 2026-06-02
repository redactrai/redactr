package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeedDefaults(t *testing.T) {
	p := Seed([]string{"evil.test"})
	if p.Image != "redactr-base:local" {
		t.Errorf("Image = %q, want redactr-base:local", p.Image)
	}
	if p.MountMode != "bind" {
		t.Errorf("MountMode = %q, want bind", p.MountMode)
	}
	if len(p.Denylist) != 1 || p.Denylist[0] != "evil.test" {
		t.Errorf("Denylist = %v, want [evil.test]", p.Denylist)
	}
}

func TestLoadMissingReturnsSeed(t *testing.T) {
	base := t.TempDir()
	p, err := Load(base, []string{"x.test"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Image != "redactr-base:local" || p.MountMode != "bind" {
		t.Errorf("expected seeded defaults, got %+v", p)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	base := t.TempDir()
	want := Policy{Image: "redactr-base:v2", MountMode: "bind", Denylist: []string{"a.test"}, Version: 7}
	if err := Save(base, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "cache", "policy.json")); err != nil {
		t.Fatalf("policy.json not written: %v", err)
	}
	got, err := Load(base, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Image != want.Image || got.MountMode != want.MountMode || got.Version != want.Version ||
		len(got.Denylist) != 1 || got.Denylist[0] != want.Denylist[0] {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}
