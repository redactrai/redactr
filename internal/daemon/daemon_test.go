package daemon

import (
	"path/filepath"
	"testing"
)

// TestEnrolledGate verifies the background loops (policy sync + monitor report)
// stay off until the daemon is enrolled.
func TestEnrolledGate(t *testing.T) {
	base := t.TempDir()
	if isEnrolled(base) {
		t.Error("unenrolled should not run background loops")
	}
}

// TestBuildStartStop verifies the daemon wires up, starts its listeners on a
// throwaway baseDir, and shuts down cleanly. No Docker / no GLiNER required
// (both degrade gracefully).
func TestBuildStartStop(t *testing.T) {
	base := t.TempDir()
	// Ephemeral binds admin+dashboard on OS-assigned ports so the test never
	// collides with a real daemon.
	d, err := Build(Options{BaseDir: base, Ephemeral: true})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := filepath.Glob(filepath.Join(base, "state", "*")); err != nil {
		t.Fatalf("state glob: %v", err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
