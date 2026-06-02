// Package devcontainer generates a .devcontainer/devcontainer.json that runs a
// project's VS Code workspace (extension host + terminal) inside a redactr
// container: pinned image, proxy/CA env, CA mount, and the hardening profile.
package devcontainer

import (
	"encoding/json"

	"github.com/rakeshguha/redactr/internal/sandbox"
)

// GenerateInput is the resolved launch policy needed to render a devcontainer.
type GenerateInput struct {
	Image      string
	ProxyAddr  string
	CACertPath string
}

// host.docker.internal is the only alias devcontainers use — the VS Code
// devcontainer CLI is Docker-backed.
const hostAlias = "host.docker.internal"

// Generate renders the devcontainer.json bytes.
func Generate(in GenerateInput) ([]byte, error) {
	port := sandbox.PortOf(in.ProxyAddr)
	containerEnv := map[string]string{}
	for _, kv := range sandbox.ProxyEnv(hostAlias, port) {
		containerEnv[kv[0]] = kv[1]
	}
	runArgs := append([]string{"--add-host", hostAlias + ":host-gateway"}, sandbox.HardeningArgs("docker")...)
	dc := map[string]any{
		"name":         "redactr",
		"image":        in.Image,
		"containerEnv": containerEnv,
		"mounts": []string{
			"source=" + in.CACertPath + ",target=" + sandbox.CAInContainer + ",type=bind,readonly",
		},
		"runArgs": runArgs,
	}
	return json.MarshalIndent(dc, "", "  ")
}
