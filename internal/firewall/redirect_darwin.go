//go:build darwin

package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

const redactrAnchor = "com.redactr"
const redactrCASubject = "Redactr Root CA"

// darwinActive is the in-process flag mirroring whether Redirect last
// succeeded. Persisted to disk via the State file so that a daemon
// crash doesn't lose the bit; this in-memory flag is for fast IsActive
// reads inside a single process lifetime.
var darwinActive atomic.Bool

// caPath holds the absolute path to the Redactr CA cert. The daemon
// sets this once at startup before calling Redirect.
var caPath atomic.Value // string

// SetCAPath records the CA cert location for the current process.
// Must be called before Redirect; otherwise Redirect returns an error.
func SetCAPath(p string) { caPath.Store(p) }

func (f *darwinFirewall) Redirect(ips []string, transparentPort int) error {
	if transparentPort <= 0 || transparentPort > 65535 {
		err := fmt.Errorf("firewall: invalid transparent port %d", transparentPort)
		slog.Error("firewall.Redirect precondition failed",
			"reason", "invalid_port",
			"transparent_port", transparentPort)
		return err
	}
	slog.Info("firewall.Redirect installing",
		"ip_count", len(ips),
		"transparent_port", transparentPort,
		"anchor", redactrAnchor)
	script := buildApplyScript(buildApplyArgs{
		Anchor:          redactrAnchor,
		IPs:             ips,
		TransparentPort: transparentPort,
	})
	if err := runWithSudo(script); err != nil {
		darwinActive.Store(false)
		slog.Error("firewall.Redirect install failed", "error", err)
		return err
	}
	slog.Info("firewall.Redirect install succeeded", "ip_count", len(ips))
	darwinActive.Store(true)
	return nil
}

// IsCATrusted reports whether the Redactr CA is currently trusted in
// the system keychain. Used by the dashboard to surface a separate
// "CA trust" status, since CA install is decoupled from pf install.
func IsCATrusted() bool {
	cmd := exec.Command("security", "find-certificate", "-c", redactrCASubject, "/Library/Keychains/System.keychain")
	return cmd.Run() == nil
}

// CACertPath returns the absolute path to the Redactr CA cert, or "" if
// not yet set via SetCAPath.
func CACertPath() string {
	cp, _ := caPath.Load().(string)
	return cp
}

func (f *darwinFirewall) Unredirect() error {
	slog.Info("firewall.Unredirect flushing", "anchor", redactrAnchor)
	script := buildRemoveScript(redactrAnchor)
	if err := runWithSudo(script); err != nil {
		slog.Error("firewall.Unredirect failed", "error", err)
		return err
	}
	darwinActive.Store(false)
	slog.Info("firewall.Unredirect succeeded")
	return nil
}

func (f *darwinFirewall) IsActive() (bool, error) {
	return darwinActive.Load(), nil
}

// runWithSudo wraps the given /bin/sh script in an
// `osascript -e 'do shell script "..." with administrator privileges'`
// invocation. macOS shows a system password dialog on the first call;
// subsequent calls within ~5 minutes do not re-prompt.
func runWithSudo(script string) error {
	// AppleScript string-escape: backslash and double-quote.
	escaped := strings.ReplaceAll(script, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	osa := fmt.Sprintf(`do shell script "%s" with administrator privileges`, escaped)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "osascript", "-e", osa)
	out, err := cmd.CombinedOutput()
	stderr := strings.TrimSpace(string(out))
	if err != nil {
		slog.Error("firewall osascript failed",
			"error", err,
			"stderr", stderr,
			"script_bytes", len(script))
		return fmt.Errorf("osascript: %w — %s", err, stderr)
	}
	if stderr != "" {
		// osascript exited 0 but the inner shell printed warnings.
		slog.Warn("firewall osascript ok with warnings", "stderr", stderr)
	}
	return nil
}
