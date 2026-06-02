//go:build integration

package integration

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestEgressDroppedOnOddPort verifies non-80/443/53 egress is blocked by the
// entrypoint's iptables rules (the raw-socket exfil boundary).
func TestEgressDroppedOnOddPort(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "image", "inspect", "redactr-base:local").Run(); err != nil {
		t.Skip("redactr-base:local not built")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Attempt an outbound TCP connection on an odd port; expect it to fail fast.
	argv := []string{
		"docker", "run", "--rm",
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "REDACTR_PROXY_HOST=host.docker.internal",
		"-e", "REDACTR_PROXY_PORT=47474",
		"redactr-base:local",
		"sh", "-c", "curl -m 5 -s -o /dev/null http://example.com:9999 && echo REACHED || echo BLOCKED",
	}
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "BLOCKED") {
		t.Fatalf("expected odd-port egress to be BLOCKED, got: %s", out)
	}
}
