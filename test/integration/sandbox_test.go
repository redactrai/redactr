//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rakeshguha/redactr/internal/sandbox"
)

// TestSandboxReachesProxyAlias verifies a container launched by the engine can
// resolve the host-gateway alias and that HTTPS_PROXY is set inside it.
func TestSandboxReachesProxyAlias(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "image", "inspect", "redactr-base:local").Run(); err != nil {
		t.Skip("redactr-base:local not built (run `make sandbox-image`)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Compose the same way the engine does, but capture stdout.
	flags := []string{"--rm"}
	flags = append(flags, sandbox.HardeningArgs("docker")...)
	flags = append(flags, sandbox.InjectionArgs(sandbox.Spec{
		ProjectDir: t.TempDir(),
		ProxyAddr:  "127.0.0.1:47474",
		CACertPath: caFixture(t),
	})...)
	argv := append(append([]string{"docker", "run"}, flags...),
		"redactr-base:local", "sh", "-c", "echo PROXY=$HTTPS_PROXY")

	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PROXY=http://host.docker.internal:47474") {
		t.Fatalf("HTTPS_PROXY not injected, got: %s", out)
	}
}

func caFixture(t *testing.T) string {
	t.Helper()
	p := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(p, []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
