package sandbox

import (
	"strings"
	"testing"
)

func TestHostAliasFor(t *testing.T) {
	if got := hostAliasFor("podman"); got != "host.containers.internal" {
		t.Errorf("podman alias = %q", got)
	}
	if got := hostAliasFor("docker"); got != "host.docker.internal" {
		t.Errorf("docker alias = %q", got)
	}
}

func TestInjectionArgsPodmanAlias(t *testing.T) {
	got := strings.Join(InjectionArgs(Spec{
		ProjectDir: "/p", ProxyAddr: "127.0.0.1:47474", CACertPath: "/ca.crt",
		HostAlias: "host.containers.internal",
	}), " ")
	if !strings.Contains(got, "host.containers.internal:host-gateway") {
		t.Errorf("missing podman add-host: %s", got)
	}
	if !strings.Contains(got, "REDACTR_PROXY_HOST=host.containers.internal") {
		t.Errorf("missing podman proxy host env: %s", got)
	}
	if strings.Contains(got, "host.docker.internal") {
		t.Errorf("should not contain docker alias: %s", got)
	}
}

func TestInjectionArgs(t *testing.T) {
	s := Spec{
		Mode:       ModeEphemeralTTY,
		Image:      "redactr-base:local",
		ProjectDir: "/home/u/proj",
		Entrypoint: []string{"claude"},
		ProxyAddr:  "127.0.0.1:47474",
		CACertPath: "/home/u/.redactr/certs/ca.crt",
	}
	got := strings.Join(InjectionArgs(s), " ")

	wants := []string{
		"--add-host host.docker.internal:host-gateway",
		"-v /home/u/proj:/work",
		"-w /work",
		"-v /home/u/.redactr/certs/ca.crt:/etc/redactr/ca.crt:ro",
		"-e HTTPS_PROXY=http://host.docker.internal:47474",
		"-e HTTP_PROXY=http://host.docker.internal:47474",
		"-e https_proxy=http://host.docker.internal:47474",
		"-e http_proxy=http://host.docker.internal:47474",
		"-e NODE_EXTRA_CA_CERTS=/etc/redactr/ca.crt",
		"-e REQUESTS_CA_BUNDLE=/etc/redactr/ca.crt",
		"-e SSL_CERT_FILE=/etc/redactr/ca.crt",
		"-e REDACTR_BOUND=1",
		"-e REDACTR_PROXY_HOST=host.docker.internal",
		"-e REDACTR_PROXY_PORT=47474",
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("injection args missing %q\ngot: %s", w, got)
		}
	}
}
