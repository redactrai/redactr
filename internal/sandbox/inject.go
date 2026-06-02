package sandbox

import "strings"

const (
	workMount = "/work"
	// CAInContainer is the in-container path the redactr CA is mounted to. The
	// devcontainer renderer references the same constant so the two front doors
	// can't drift.
	CAInContainer = "/etc/redactr/ca.crt"

	dockerHostAlias = "host.docker.internal"
	podmanHostAlias = "host.containers.internal"
)

// ProxyEnv returns the canonical proxy/CA environment a bound container needs,
// as ordered key/value pairs. alias is the in-container host DNS alias and port
// the host proxy port. Both InjectionArgs (docker flags) and the devcontainer
// renderer (devcontainer.json) build from this single source so the injected
// facts stay identical across front doors.
func ProxyEnv(alias, port string) [][2]string {
	proxyURL := "http://" + alias + ":" + port
	return [][2]string{
		{"HTTPS_PROXY", proxyURL},
		{"HTTP_PROXY", proxyURL},
		{"https_proxy", proxyURL},
		{"http_proxy", proxyURL},
		{"NODE_EXTRA_CA_CERTS", CAInContainer},
		{"REQUESTS_CA_BUNDLE", CAInContainer},
		{"SSL_CERT_FILE", CAInContainer},
		{"REDACTR_BOUND", "1"},
		{"REDACTR_PROXY_HOST", alias},
		{"REDACTR_PROXY_PORT", port},
	}
}

// hostAliasFor returns the in-container DNS alias for reaching the host proxy,
// per container runtime.
func hostAliasFor(runtime string) string {
	if runtime == "podman" {
		return podmanHostAlias
	}
	return dockerHostAlias
}

// InjectionArgs returns the launch-time mount/env flags. It injects the project
// bind-mount, the CA read-only, proxy env pointing at the host alias, and
// REDACTR_BOUND=1. s.HostAlias selects the runtime alias (empty => Docker).
func InjectionArgs(s Spec) []string {
	alias := s.HostAlias
	if alias == "" {
		alias = dockerHostAlias
	}
	port := PortOf(s.ProxyAddr)
	args := []string{
		"--add-host", alias + ":host-gateway",
		"-v", s.ProjectDir + ":" + workMount,
		"-w", workMount,
		"-v", s.CACertPath + ":" + CAInContainer + ":ro",
	}
	for _, kv := range ProxyEnv(alias, port) {
		args = append(args, "-e", kv[0]+"="+kv[1])
	}
	return args
}

// PortOf extracts the port from a host:port string.
func PortOf(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		return hostPort[i+1:]
	}
	return hostPort
}
