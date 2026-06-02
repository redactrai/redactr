package sandbox

import "testing"

func TestSpecValidate(t *testing.T) {
	tests := []struct {
		name    string
		spec    Spec
		wantErr bool
	}{
		{"valid ephemeral", Spec{Mode: ModeEphemeralTTY, Image: "redactr-base:local", ProjectDir: "/tmp/p", Entrypoint: []string{"claude"}}, false},
		{"valid stdio", Spec{Mode: ModeStdioAttached, Image: "redactr-base:local", ProjectDir: "/tmp/p", Entrypoint: []string{"mcp"}}, false},
		{"missing image", Spec{Mode: ModeEphemeralTTY, ProjectDir: "/tmp/p", Entrypoint: []string{"claude"}}, true},
		{"missing project dir", Spec{Mode: ModeEphemeralTTY, Image: "redactr-base:local", Entrypoint: []string{"claude"}}, true},
		{"missing entrypoint", Spec{Mode: ModeEphemeralTTY, Image: "redactr-base:local", ProjectDir: "/tmp/p"}, true},
		{"unsupported mode", Spec{Mode: ModeWorkspaceRemote, Image: "redactr-base:local", ProjectDir: "/tmp/p", Entrypoint: []string{"x"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
