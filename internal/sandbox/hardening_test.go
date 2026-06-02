package sandbox

import (
	"strings"
	"testing"
)

func TestHardeningArgs(t *testing.T) {
	got := strings.Join(HardeningArgs("docker"), " ")
	must := []string{
		"--cap-drop ALL",
		"--cap-add NET_ADMIN",
		"--cap-add NET_RAW",
		"--security-opt no-new-privileges",
		"--read-only",
		"--tmpfs /tmp",
		"--tmpfs /home/redactr:uid=1000,mode=0700",
		"--pids-limit",
		"--memory",
	}
	for _, m := range must {
		if !strings.Contains(got, m) {
			t.Errorf("hardening args missing %q\ngot: %s", m, got)
		}
	}
	for _, banned := range []string{"--privileged", "docker.sock", "--network host", "--net=host"} {
		if strings.Contains(got, banned) {
			t.Errorf("hardening args must never contain %q\ngot: %s", banned, got)
		}
	}
}

func TestHardeningPodmanKeepID(t *testing.T) {
	got := strings.Join(HardeningArgs("podman"), " ")
	if !strings.Contains(got, "--userns keep-id") {
		t.Errorf("podman hardening should set --userns keep-id\ngot: %s", got)
	}
}
