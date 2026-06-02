package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDevcontainerRefusesClobber(t *testing.T) {
	proj := t.TempDir()
	p, err := writeDevcontainer(proj, []byte(`{"x":1}`), false)
	if err != nil || p == "" {
		t.Fatalf("writeDevcontainer: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if _, err := writeDevcontainer(proj, []byte(`{"x":2}`), false); err == nil {
		t.Error("expected clobber refusal without --force")
	}
	if _, err := writeDevcontainer(proj, []byte(`{"x":3}`), true); err != nil {
		t.Errorf("force write: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(proj, ".devcontainer", "devcontainer.json"))
	if string(b) != `{"x":3}` {
		t.Errorf("content = %s", b)
	}
}

func TestLaunchDevcontainerInvokesCLI(t *testing.T) {
	var got []string
	run := func(name string, args ...string) error { got = append([]string{name}, args...); return nil }
	if err := launchDevcontainer("/proj", run); err != nil {
		t.Fatalf("launchDevcontainer: %v", err)
	}
	if len(got) < 3 || got[0] != "devcontainer" || got[1] != "up" || got[len(got)-1] != "/proj" {
		t.Fatalf("argv = %v", got)
	}
}
