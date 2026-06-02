package keys

import (
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate#1: %v", err)
	}
	if k1 == nil || k1.Curve == nil {
		t.Fatal("nil key")
	}
	k2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate#2: %v", err)
	}
	if k1.D.Cmp(k2.D) != 0 {
		t.Error("expected the same private key on reload")
	}
}
