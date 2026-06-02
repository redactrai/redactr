package sandbox

import (
	"context"
	"strings"
	"testing"
)

type captureRunner struct{ argv []string }

func (c *captureRunner) Run(_ context.Context, argv []string) error {
	c.argv = argv
	return nil
}

func TestEngineLaunchComposesArgv(t *testing.T) {
	cap := &captureRunner{}
	eng := &Engine{Runtime: cliRuntime{bin: "docker"}, Runner: cap}

	spec := Spec{
		Mode:       ModeEphemeralTTY,
		Image:      "redactr-base:local",
		ProjectDir: "/home/u/proj",
		Entrypoint: []string{"claude", "--version"},
		ProxyAddr:  "127.0.0.1:47474",
		CACertPath: "/home/u/.redactr/certs/ca.crt",
	}
	if err := eng.Launch(context.Background(), spec); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	got := strings.Join(cap.argv, " ")

	for _, w := range []string{
		"docker run",
		"--rm",
		"-it",
		"--cap-drop ALL",
		"-v /home/u/proj:/work",
		"-e REDACTR_BOUND=1",
		"redactr-base:local claude --version",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("argv missing %q\ngot: %s", w, got)
		}
	}
	if strings.Index(got, "redactr-base:local") > strings.Index(got, "claude --version") {
		t.Errorf("image must come before entrypoint\ngot: %s", got)
	}
}

func TestEngineLaunchRejectsStdioMode(t *testing.T) {
	eng := &Engine{Runtime: cliRuntime{bin: "docker"}, Runner: &captureRunner{}}
	err := eng.Launch(context.Background(), Spec{Mode: ModeStdioAttached, Image: "x", ProjectDir: "/p", Entrypoint: []string{"y"}})
	if err == nil {
		t.Fatal("Launch must reject ModeStdioAttached (use StdioRunArgs)")
	}
}

func TestEngineLaunchRejectsUnsupportedMode(t *testing.T) {
	eng := &Engine{Runtime: cliRuntime{bin: "docker"}, Runner: &captureRunner{}}
	err := eng.Launch(context.Background(), Spec{Mode: ModeWorkspaceRemote, Image: "x", ProjectDir: "/p", Entrypoint: []string{"y"}})
	if err == nil {
		t.Fatal("expected error for unsupported mode")
	}
}

func TestStdioRunArgs(t *testing.T) {
	eng := &Engine{Runtime: cliRuntime{bin: "docker"}}
	argv, err := eng.StdioRunArgs(Spec{
		Mode: ModeStdioAttached, Image: "redactr-base:local", ProjectDir: "/home/u/proj",
		Entrypoint: []string{"mcp-server", "--flag"}, ProxyAddr: "127.0.0.1:47474", CACertPath: "/ca.crt",
	})
	if err != nil {
		t.Fatalf("StdioRunArgs: %v", err)
	}
	got := strings.Join(argv, " ")
	if !strings.Contains(got, "docker run --rm -i ") || strings.Contains(got, "-it") {
		t.Errorf("expected --rm -i (no tty): %s", got)
	}
	for _, w := range []string{"--cap-drop ALL", "-v /home/u/proj:/work", "redactr-base:local mcp-server --flag"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in %s", w, got)
		}
	}
}
