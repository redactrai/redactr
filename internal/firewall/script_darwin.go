//go:build darwin

package firewall

import (
	"fmt"
	"strings"
)

type buildApplyArgs struct {
	Anchor          string // pf anchor, typically "com.redactr"
	IPs             []string
	TransparentPort int
}

// buildApplyScript returns a /bin/sh script that, when run with admin
// privileges, writes pf rdr rules redirecting traffic to the supplied
// IPs into the transparent listener port. It does NOT touch the system
// keychain — CA cert trust is a separate concern (see Manager.EnsureCA),
// because `security add-trusted-cert` requires a GUI trust dialog that
// macOS cannot render inside an osascript-launched non-interactive shell.
//
// The returned script is suitable for use as the argument to
// `osascript -e 'do shell script "<script>" with administrator privileges'`.
func buildApplyScript(a buildApplyArgs) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	// Note: no `set -e`. We want pfctl errors visible but a partial
	// failure on rule install shouldn't prevent the rest from running.
	// Flush old rules in our anchor (ignore "no rules" error).
	fmt.Fprintf(&b, "pfctl -a %q -F all 2>/dev/null || true\n", a.Anchor)
	// Build rule list.
	var rules strings.Builder
	for _, ip := range a.IPs {
		fmt.Fprintf(&rules, "rdr pass on lo0 inet proto tcp from any to %s port 443 -> 127.0.0.1 port %d\n", ip, a.TransparentPort)
	}
	// Pipe rules via heredoc to avoid escape headaches with multi-line stdin.
	fmt.Fprintf(&b, "pfctl -a %q -f - <<'__REDACTR_RULES__'\n%s__REDACTR_RULES__\n", a.Anchor, rules.String())
	// Enable pf if not already (returns non-zero when already enabled — ignore).
	b.WriteString("pfctl -E 2>/dev/null || true\n")
	return b.String()
}

// buildRemoveScript returns a /bin/sh script that flushes all rules
// from the redactr pf anchor. Does NOT remove the CA from the keychain.
func buildRemoveScript(anchor string) string {
	return fmt.Sprintf("#!/bin/sh\nset -e\npfctl -a %q -F all 2>/dev/null || true\n", anchor)
}
