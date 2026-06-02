package devcontainer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	raw, err := Generate(GenerateInput{
		Image: "reg/acme/tools@sha256:abc", ProxyAddr: "127.0.0.1:47474", CACertPath: "/home/u/.redactr/certs/ca.crt",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var dc struct {
		Image        string            `json:"image"`
		ContainerEnv map[string]string `json:"containerEnv"`
		Mounts       []string          `json:"mounts"`
		RunArgs      []string          `json:"runArgs"`
	}
	if err := json.Unmarshal(raw, &dc); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, raw)
	}
	if dc.Image != "reg/acme/tools@sha256:abc" {
		t.Errorf("image = %q", dc.Image)
	}
	if dc.ContainerEnv["HTTPS_PROXY"] != "http://host.docker.internal:47474" {
		t.Errorf("HTTPS_PROXY = %q", dc.ContainerEnv["HTTPS_PROXY"])
	}
	if dc.ContainerEnv["REDACTR_BOUND"] != "1" || dc.ContainerEnv["NODE_EXTRA_CA_CERTS"] != "/etc/redactr/ca.crt" {
		t.Errorf("env = %+v", dc.ContainerEnv)
	}
	if len(dc.Mounts) == 0 || !strings.Contains(dc.Mounts[0], "/home/u/.redactr/certs/ca.crt") {
		t.Errorf("mounts = %v", dc.Mounts)
	}
	ra := strings.Join(dc.RunArgs, " ")
	if !strings.Contains(ra, "--cap-drop ALL") || !strings.Contains(ra, "host.docker.internal:host-gateway") {
		t.Errorf("runArgs = %v", dc.RunArgs)
	}
}
