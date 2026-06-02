package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDetectPrefersDocker(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "docker")
	writeFakeBin(t, dir, "podman")
	t.Setenv("PATH", dir)

	rt, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.Name() != "docker" {
		t.Errorf("Name() = %q, want docker", rt.Name())
	}
}

func TestDetectFallsBackToPodman(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "podman")
	t.Setenv("PATH", dir)

	rt, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if rt.Name() != "podman" {
		t.Errorf("Name() = %q, want podman", rt.Name())
	}
}

func TestDetectNoneFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := Detect(); err == nil {
		t.Fatal("expected error when no runtime found")
	}
}

func TestRunArgsOrder(t *testing.T) {
	rt := cliRuntime{bin: "docker"}
	got := rt.RunArgs(
		[]string{"--rm", "-it"},
		"redactr-base:local",
		[]string{"claude", "--version"},
	)
	want := []string{"docker", "run", "--rm", "-it", "redactr-base:local", "claude", "--version"}
	if !slices.Equal(got, want) {
		t.Errorf("RunArgs() = %v, want %v", got, want)
	}
}

func writeFakeBin(t *testing.T, dir, name string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}
