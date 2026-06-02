package cli

import "testing"

func TestKnownAgentImage(t *testing.T) {
	tests := []struct {
		tool   string
		ok     bool
		entry0 string
	}{
		{"claude", true, "claude"},
		{"codex", true, "codex"},
		{"copilot", true, "copilot"},
		{"unknown", false, ""},
	}
	for _, tt := range tests {
		entry, ok := knownAgentEntrypoint(tt.tool)
		if ok != tt.ok {
			t.Fatalf("%s: ok = %v, want %v", tt.tool, ok, tt.ok)
		}
		if ok && entry[0] != tt.entry0 {
			t.Errorf("%s: entry[0] = %q, want %q", tt.tool, entry[0], tt.entry0)
		}
	}
}

func TestSpecFromPolicyRejectsDiffback(t *testing.T) {
	_, err := specFromLaunchInfo("claude", nil, "/cwd", "/ca.crt",
		launchInfo{Image: "img", MountMode: "diffback", ProxyAddr: "127.0.0.1:47474"})
	if err == nil {
		t.Fatal("expected diffback mount mode to be rejected (not yet supported)")
	}
}

func TestSpecFromPolicyBindOK(t *testing.T) {
	spec, err := specFromLaunchInfo("claude", []string{"--version"}, "/cwd", "/ca.crt",
		launchInfo{Image: "redactr-base:local", MountMode: "bind", ProxyAddr: "127.0.0.1:47474"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Image != "redactr-base:local" || spec.ProjectDir != "/cwd" || spec.ProxyAddr != "127.0.0.1:47474" {
		t.Errorf("spec = %+v", spec)
	}
	if len(spec.Entrypoint) != 2 || spec.Entrypoint[0] != "claude" || spec.Entrypoint[1] != "--version" {
		t.Errorf("entrypoint = %v", spec.Entrypoint)
	}
}
