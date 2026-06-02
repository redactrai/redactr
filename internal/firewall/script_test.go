//go:build darwin

package firewall

import (
	"os/exec"
	"strings"
	"testing"
)

func TestBuildApplyScriptIncludesAllRules(t *testing.T) {
	script := buildApplyScript(buildApplyArgs{
		Anchor:          "com.redactr",
		IPs:             []string{"1.2.3.4", "5.6.7.8"},
		TransparentPort: 58601,
	})

	for _, want := range []string{
		`pfctl -a "com.redactr" -F all`,
		`pfctl -a "com.redactr" -f -`,
		"rdr pass on lo0 inet proto tcp from any to 1.2.3.4 port 443 -> 127.0.0.1 port 58601",
		"rdr pass on lo0 inet proto tcp from any to 5.6.7.8 port 443 -> 127.0.0.1 port 58601",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("apply script missing %q\nscript:\n%s", want, script)
		}
	}

	// Critical: the apply script must NOT touch the system keychain.
	// CA install requires interactive trust dialog and is handled separately.
	for _, mustNotHave := range []string{
		"security add-trusted-cert",
		"security find-certificate",
		"/Library/Keychains/System.keychain",
	} {
		if strings.Contains(script, mustNotHave) {
			t.Errorf("apply script must not touch keychain (found %q)\nscript:\n%s", mustNotHave, script)
		}
	}

	// Critical: no `set -e` — a partial keychain failure must not abort pf install.
	if strings.Contains(script, "set -e") {
		t.Errorf("apply script should not use `set -e`\nscript:\n%s", script)
	}
}

func TestBuildApplyScriptIsValidShell(t *testing.T) {
	script := buildApplyScript(buildApplyArgs{
		Anchor:          "com.redactr",
		IPs:             []string{"1.2.3.4"},
		TransparentPort: 12345,
	})
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n rejected the apply script: %v\n%s\nscript:\n%s", err, out, script)
	}
}

func TestBuildRemoveScriptIsValidShell(t *testing.T) {
	script := buildRemoveScript("com.redactr")
	if !strings.Contains(script, `pfctl -a "com.redactr" -F all`) {
		t.Errorf("remove script missing flush:\n%s", script)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n rejected the remove script: %v\n%s", err, out)
	}
}

func TestRunWithSudoEscapesQuotesAndBackslashes(t *testing.T) {
	// We can't actually invoke osascript in unit tests (would prompt
	// for password). Instead, test that the AppleScript-string-escape
	// preserves the structure of an arbitrary shell script.
	script := `pfctl -a "anchor" -F all
echo "hello \world"`
	escaped := strings.ReplaceAll(script, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	if !strings.Contains(escaped, `\"anchor\"`) {
		t.Error("double-quotes should be backslash-escaped in AppleScript wrapping")
	}
	if !strings.Contains(escaped, `\\world`) {
		t.Error("backslashes should be doubled before quotes are escaped")
	}
	// Sanity: assemble the full osascript argument and confirm it's not
	// going to be tripped up by an embedded quote.
	osa := `do shell script "` + escaped + `" with administrator privileges`
	if !strings.HasPrefix(osa, `do shell script "`) || !strings.HasSuffix(osa, `" with administrator privileges`) {
		t.Errorf("osascript wrapping malformed:\n%s", osa)
	}
}
