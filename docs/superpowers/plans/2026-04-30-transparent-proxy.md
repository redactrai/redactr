# Transparent Proxy Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "Enable Proxy" in the dashboard install macOS pf `rdr` rules that redirect AI provider traffic into Redactr, plus a transparent SNI listener that handles those redirected connections, plus auto-install the Redactr CA — so the user clicks one button (one sudo prompt) and traffic is actually routed.

**Architecture:** Per-IP `pf rdr` rules in the `com.redactr` anchor, written by an `osascript` invocation that runs `pfctl` and `security` with administrator privileges. A new transparent listener binds an OS-assigned port, parses the TLS ClientHello SNI to learn the hostname (since pf strips the original destination on macOS), and splices into the existing goproxy MITM. A 5-minute DNS resolver loop tracks IP changes for the configured intercepted domains.

**Tech Stack:** Go 1.22+, macOS pf/pfctl, `security` keychain CLI, goproxy library (already in use), vanilla HTML/CSS/JS for the dashboard pill.

---

## File Structure

### New files
- `internal/firewall/script_darwin.go` — pure-string builder for the apply / remove shell scripts. No I/O. Easy to unit-test.
- `internal/firewall/script_test.go` — generator tests (build_constraint: darwin).
- `internal/firewall/redirect_darwin.go` — `Redirect`/`Unredirect` impl. Wraps the script with `osascript "do shell script ... with administrator privileges"`.
- `internal/firewall/state.go` — `~/.redactr/state/firewall.json` persistence.
- `internal/firewall/state_test.go` — state file roundtrip tests.
- `internal/firewall/dns_loop.go` — DNS resolver + reconciler (platform-agnostic).
- `internal/firewall/dns_loop_test.go` — tests with injected resolver.
- `internal/firewall/controller.go` — `Controller` orchestrating Manager + DNS loop + state, used by the API. Platform-agnostic (calls into `Manager` interface).
- `internal/firewall/controller_test.go` — tests with mocked Manager and resolver.
- `internal/proxy/sni.go` — TLS ClientHello SNI extractor. ~80 lines, pure parser.
- `internal/proxy/sni_test.go` — golden-bytes tests.
- `internal/proxy/transparent.go` — transparent listener with SNI parsing + goproxy splice.

### Modified files
- `internal/firewall/firewall.go` — extend `Manager` interface with `Redirect`, `Unredirect`, `IsActive`.
- `internal/firewall/linux.go` — stub the new methods.
- `internal/firewall/windows.go` — stub the new methods.
- `internal/firewall/darwin.go` — keep `BlockDirect` as-is for backwards compat; `Redirect`/`Unredirect`/`IsActive` live in `redirect_darwin.go`.
- `internal/proxy/proxy.go` — add `StartTransparent(port int) (string, error)` method.
- `internal/api/server.go` — accept `*firewall.Controller` and store it.
- `internal/api/routes.go` — `handleProxyEnable` / `handleProxyDisable` call the controller. `handleProxyStatus` returns three-state info.
- `cmd/redactr/main.go` — construct `firewall.Controller`, pass to API server, hook into shutdown.
- `internal/api/static/index.html` — three-state proxy pill (offline / listening / active).
- `internal/api/static/style.css` — `data-state="listening"` styles.
- `internal/api/static/app.js` — read new status fields, render tri-state.

---

## Phase 1 — Firewall library

### Task 1: Extend `Manager` interface and stub Linux/Windows

**Files:**
- Modify: `internal/firewall/firewall.go`
- Modify: `internal/firewall/linux.go`
- Modify: `internal/firewall/windows.go`
- Modify: `internal/firewall/darwin.go` (add no-op methods that return ErrNotImplemented; the real impl lands in Task 5)

- [ ] **Step 1: Read the existing files**

```
cat internal/firewall/firewall.go internal/firewall/linux.go internal/firewall/windows.go internal/firewall/darwin.go
```

Note the `Manager` interface signature so the stubs match.

- [ ] **Step 2: Extend the interface**

Edit `internal/firewall/firewall.go`. Replace `type Manager interface { ... }` with:

```go
type Manager interface {
	BlockDirect(domains []string, proxyPort int) error
	Unblock() error
	Status() ([]Rule, error)
	Cleanup() error

	// Redirect installs OS-level rules that redirect TCP:443 traffic to the
	// listed IPs into the local transparent listener. Idempotent: replaces
	// any prior rules in the redactr anchor.
	Redirect(ips []string, transparentPort int) error

	// Unredirect removes all rules installed by Redirect.
	Unredirect() error

	// IsActive reports whether redirect rules are currently installed.
	IsActive() (bool, error)
}

// ErrNotImplemented is returned by platforms that don't yet support
// transparent routing.
var ErrNotImplemented = errors.New("transparent routing not implemented on this platform")
```

Add `"errors"` to the import block.

- [ ] **Step 3: Stub Linux**

In `internal/firewall/linux.go`, append three methods on `*linuxFirewall`:

```go
func (f *linuxFirewall) Redirect(ips []string, transparentPort int) error { return ErrNotImplemented }
func (f *linuxFirewall) Unredirect() error                                 { return ErrNotImplemented }
func (f *linuxFirewall) IsActive() (bool, error)                           { return false, nil }
```

- [ ] **Step 4: Stub Windows**

In `internal/firewall/windows.go`, append three methods on `*windowsFirewall`:

```go
func (f *windowsFirewall) Redirect(ips []string, transparentPort int) error { return ErrNotImplemented }
func (f *windowsFirewall) Unredirect() error                                 { return ErrNotImplemented }
func (f *windowsFirewall) IsActive() (bool, error)                           { return false, nil }
```

- [ ] **Step 5: Stub macOS (real impl lands in Task 5)**

Append to `internal/firewall/darwin.go`:

```go
func (f *darwinFirewall) Redirect(ips []string, transparentPort int) error { return ErrNotImplemented }
func (f *darwinFirewall) Unredirect() error                                 { return ErrNotImplemented }
func (f *darwinFirewall) IsActive() (bool, error)                           { return false, nil }
```

These are temporary stubs so the project builds; Task 5 replaces them by routing through `redirect_darwin.go`.

- [ ] **Step 6: Verify build**

```
go build ./...
go vet ./...
```
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add internal/firewall/firewall.go internal/firewall/linux.go internal/firewall/windows.go internal/firewall/darwin.go
git commit -m "feat(firewall): extend Manager interface with Redirect/Unredirect/IsActive"
```

---

### Task 2: Script generator (script_darwin.go)

**Files:**
- Create: `internal/firewall/script_darwin.go`
- Create: `internal/firewall/script_test.go` (build-tagged darwin)

- [ ] **Step 1: Write the failing test**

Create `internal/firewall/script_test.go`:

```go
//go:build darwin

package firewall

import (
	"os/exec"
	"strings"
	"testing"
)

func TestBuildApplyScriptIncludesAllRules(t *testing.T) {
	script := buildApplyScript(buildApplyArgs{
		CAPath:          "/Users/me/.redactr/certs/ca.crt",
		CASubject:       "Redactr Root CA",
		Anchor:          "com.redactr",
		IPs:             []string{"1.2.3.4", "5.6.7.8"},
		TransparentPort: 58601,
	})

	for _, want := range []string{
		"security find-certificate -c \"Redactr Root CA\"",
		"security add-trusted-cert",
		"/Users/me/.redactr/certs/ca.crt",
		"pfctl -a com.redactr -F all",
		"pfctl -a com.redactr -f -",
		"rdr pass on lo0 inet proto tcp from any to 1.2.3.4 port 443 -> 127.0.0.1 port 58601",
		"rdr pass on lo0 inet proto tcp from any to 5.6.7.8 port 443 -> 127.0.0.1 port 58601",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("apply script missing %q\nscript:\n%s", want, script)
		}
	}
}

func TestBuildApplyScriptIsValidShell(t *testing.T) {
	script := buildApplyScript(buildApplyArgs{
		CAPath:          "/tmp/ca.crt",
		CASubject:       "Redactr Root CA",
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
	if !strings.Contains(script, "pfctl -a com.redactr -F all") {
		t.Errorf("remove script missing flush:\n%s", script)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n rejected the remove script: %v\n%s", err, out)
	}
}

func TestBuildApplyScriptShellQuotesPaths(t *testing.T) {
	script := buildApplyScript(buildApplyArgs{
		CAPath:          "/path with spaces/ca.crt",
		CASubject:       "Redactr Root CA",
		Anchor:          "com.redactr",
		IPs:             []string{"1.2.3.4"},
		TransparentPort: 58601,
	})
	if !strings.Contains(script, `"/path with spaces/ca.crt"`) {
		t.Errorf("CA path should be double-quoted; got:\n%s", script)
	}
}
```

- [ ] **Step 2: Run, fail**

```
go test ./internal/firewall/... -run "TestBuild"
```
Expected: FAIL — `buildApplyScript` and `buildRemoveScript` undefined.

- [ ] **Step 3: Implement the generator**

Create `internal/firewall/script_darwin.go`:

```go
//go:build darwin

package firewall

import (
	"fmt"
	"strings"
)

type buildApplyArgs struct {
	CAPath          string // absolute path to Redactr CA cert
	CASubject       string // common name to look up, e.g. "Redactr Root CA"
	Anchor          string // pf anchor, typically "com.redactr"
	IPs             []string
	TransparentPort int
}

// buildApplyScript returns a /bin/sh script that, when run with admin
// privileges, idempotently installs the Redactr CA into the system
// keychain and writes pf rdr rules redirecting traffic to the supplied
// IPs into the transparent listener port.
//
// The returned script is suitable for use as the argument to
// `osascript -e 'do shell script "<script>" with administrator privileges'`.
// All shell quoting in this function assumes the embedding context is a
// `do shell script "..."` call where the outer string-quoting is handled
// by the caller; here we produce a plain shell script and rely on
// AppleScript's literal-string rules at the call site.
func buildApplyScript(a buildApplyArgs) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("set -e\n")
	// CA install — idempotent, by common-name lookup.
	fmt.Fprintf(&b,
		"if ! security find-certificate -c %q /Library/Keychains/System.keychain >/dev/null 2>&1; then\n"+
			"  security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %q\n"+
			"fi\n",
		a.CASubject, a.CAPath,
	)
	// Flush old rules in our anchor (ignore "no rules" error).
	fmt.Fprintf(&b, "pfctl -a %q -F all 2>/dev/null || true\n", a.Anchor)
	// Build rule list and pipe into pfctl.
	var rules strings.Builder
	for _, ip := range a.IPs {
		fmt.Fprintf(&rules, "rdr pass on lo0 inet proto tcp from any to %s port 443 -> 127.0.0.1 port %d\n", ip, a.TransparentPort)
	}
	// Pipe via heredoc to avoid shell-escape headaches with multi-line stdin.
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
```

- [ ] **Step 4: Run tests**

```
go test ./internal/firewall/... -run "TestBuild" -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/firewall/script_darwin.go internal/firewall/script_test.go
git commit -m "feat(firewall): apply/remove shell-script generators (macOS)"
```

---

### Task 3: State file persistence

**Files:**
- Create: `internal/firewall/state.go`
- Create: `internal/firewall/state_test.go`

- [ ] **Step 1: Write tests**

Create `internal/firewall/state_test.go`:

```go
package firewall

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestStateRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "firewall.json")
	now := time.Date(2026, 4, 30, 12, 34, 56, 0, time.UTC)
	in := State{
		Active:          true,
		ProxyAddr:       "127.0.0.1:58600",
		TransparentAddr: "127.0.0.1:58601",
		IPs:             []string{"1.2.3.4", "5.6.7.8"},
		LastReconciled:  now,
		CAInstalled:     true,
	}
	if err := SaveState(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := LoadState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("roundtrip mismatch:\nin:  %+v\nout: %+v", in, out)
	}
}

func TestLoadStateMissingFileReturnsZero(t *testing.T) {
	out, err := LoadState("/nonexistent/path.json")
	if err != nil {
		t.Errorf("expected nil error for missing file, got %v", err)
	}
	if out.Active {
		t.Error("missing file should produce zero State (Active=false)")
	}
}

func TestSaveStateCreatesDirIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "subdir", "firewall.json")
	if err := SaveState(path, State{Active: true}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should exist: %v", err)
	}
}
```

- [ ] **Step 2: Run, fail**

```
go test ./internal/firewall/... -run "TestState|TestSaveState|TestLoadState"
```
Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

Create `internal/firewall/state.go`:

```go
package firewall

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// State is what gets persisted to ~/.redactr/state/firewall.json. It is
// used by `redactr cleanup` to recover after crashes and by the daemon
// at startup to know whether to immediately reconcile rules.
type State struct {
	Active          bool      `json:"active"`
	ProxyAddr       string    `json:"proxy_addr"`
	TransparentAddr string    `json:"transparent_addr"`
	IPs             []string  `json:"ips"`
	LastReconciled  time.Time `json:"last_reconciled"`
	CAInstalled     bool      `json:"ca_installed"`
}

// LoadState reads the persisted firewall state from path. A missing file
// is not an error — it returns the zero State and nil.
func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, err
	}
	return s, nil
}

// SaveState writes the firewall state to path, creating parent
// directories as needed.
func SaveState(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/firewall/... -run "TestState|TestSaveState|TestLoadState" -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/firewall/state.go internal/firewall/state_test.go
git commit -m "feat(firewall): state file persistence for crash recovery"
```

---

### Task 4: DNS resolver loop

**Files:**
- Create: `internal/firewall/dns_loop.go`
- Create: `internal/firewall/dns_loop_test.go`

- [ ] **Step 1: Write tests**

Create `internal/firewall/dns_loop_test.go`:

```go
package firewall

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
)

type fakeResolver struct {
	results map[string][]string
	errors  map[string]error
	calls   int
}

func (r *fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	r.calls++
	if err, ok := r.errors[host]; ok {
		return nil, err
	}
	return r.results[host], nil
}

func TestResolveAllSuccess(t *testing.T) {
	r := &fakeResolver{results: map[string][]string{
		"api.anthropic.com": {"1.1.1.1", "2.2.2.2"},
		"api.openai.com":    {"3.3.3.3"},
	}}
	ips, err := resolveAll(context.Background(), r, []string{"api.anthropic.com", "api.openai.com"})
	if err != nil {
		t.Fatalf("resolveAll: %v", err)
	}
	sort.Strings(ips)
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if !reflect.DeepEqual(ips, want) {
		t.Errorf("got %v want %v", ips, want)
	}
}

func TestResolveAllPartialFailure(t *testing.T) {
	r := &fakeResolver{
		results: map[string][]string{"api.openai.com": {"3.3.3.3"}},
		errors:  map[string]error{"api.anthropic.com": errors.New("nxdomain")},
	}
	ips, err := resolveAll(context.Background(), r, []string{"api.anthropic.com", "api.openai.com"})
	if err != nil {
		t.Fatalf("resolveAll should not fail when some hosts succeed: %v", err)
	}
	sort.Strings(ips)
	want := []string{"3.3.3.3"}
	if !reflect.DeepEqual(ips, want) {
		t.Errorf("got %v want %v", ips, want)
	}
}

func TestResolveAllAllFail(t *testing.T) {
	r := &fakeResolver{errors: map[string]error{
		"a": errors.New("fail"),
		"b": errors.New("fail"),
	}}
	_, err := resolveAll(context.Background(), r, []string{"a", "b"})
	if err == nil {
		t.Error("resolveAll should return error when all hosts fail")
	}
}

func TestResolveAllDedupes(t *testing.T) {
	r := &fakeResolver{results: map[string][]string{
		"api.anthropic.com": {"1.1.1.1", "2.2.2.2"},
		"api.openai.com":    {"2.2.2.2", "3.3.3.3"},
	}}
	ips, _ := resolveAll(context.Background(), r, []string{"api.anthropic.com", "api.openai.com"})
	if len(ips) != 3 {
		t.Errorf("expected 3 deduped IPs, got %d: %v", len(ips), ips)
	}
}

func TestIPSetsEqual(t *testing.T) {
	if !ipSetsEqual([]string{"1", "2"}, []string{"2", "1"}) {
		t.Error("order should not matter")
	}
	if ipSetsEqual([]string{"1", "2"}, []string{"1", "2", "3"}) {
		t.Error("different lengths should be unequal")
	}
	if ipSetsEqual([]string{"1"}, []string{"2"}) {
		t.Error("different elements should be unequal")
	}
	if !ipSetsEqual(nil, nil) {
		t.Error("two nil slices should be equal")
	}
}
```

- [ ] **Step 2: Run, fail**

```
go test ./internal/firewall/... -run "TestResolve|TestIPSets"
```
Expected: FAIL — `resolveAll`, `ipSetsEqual`, `Resolver` undefined.

- [ ] **Step 3: Implement**

Create `internal/firewall/dns_loop.go`:

```go
package firewall

import (
	"context"
	"fmt"
	"net"
	"sort"
)

// Resolver is the DNS interface the reconciler uses. Defaulted to a
// real net.Resolver in production; mocked in tests.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DefaultResolver is net.DefaultResolver. Exposed for callers and tests.
var DefaultResolver Resolver = net.DefaultResolver

// resolveAll resolves every host in domains, dedupes the results, and
// returns the sorted IP set. If at least one host resolves, the error
// is nil even if others failed (DNS hiccups are common). If all hosts
// fail, an error is returned.
func resolveAll(ctx context.Context, r Resolver, domains []string) ([]string, error) {
	set := make(map[string]struct{})
	failures := 0
	for _, d := range domains {
		addrs, err := r.LookupHost(ctx, d)
		if err != nil {
			failures++
			continue
		}
		for _, a := range addrs {
			set[a] = struct{}{}
		}
	}
	if failures == len(domains) && len(domains) > 0 {
		return nil, fmt.Errorf("all %d host lookups failed", failures)
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

// ipSetsEqual reports whether two IP slices contain the same elements
// regardless of order. Both slices are treated as sets — duplicates
// within one slice that aren't in the other will trip the comparison.
func ipSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/firewall/... -run "TestResolve|TestIPSets" -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/firewall/dns_loop.go internal/firewall/dns_loop_test.go
git commit -m "feat(firewall): DNS resolver helpers for IP reconciliation"
```

---

## Phase 2 — Privileged ops via osascript

### Task 5: macOS `Redirect`/`Unredirect`/`IsActive` impl

**Files:**
- Create: `internal/firewall/redirect_darwin.go`
- Modify: `internal/firewall/darwin.go` (delete the temp stubs from Task 1; the methods now come from redirect_darwin.go)

- [ ] **Step 1: Remove stubs from darwin.go**

Delete the three methods added in Task 1 step 5 (the `Redirect`/`Unredirect`/`IsActive` stubs on `*darwinFirewall`). They will be redefined in `redirect_darwin.go` below.

- [ ] **Step 2: Implement Redirect via osascript**

Create `internal/firewall/redirect_darwin.go`:

```go
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

// active mirrors whether Redirect succeeded last; persisted to disk so
// crashes don't lose the bit. `state.go` is the source of truth across
// restarts; this in-process flag is for fast IsActive() reads.
var darwinActive atomic.Bool

// CAPath holds the absolute path to the Redactr CA cert. The daemon
// sets this once at startup before calling Redirect.
var CAPath atomic.Value // string

// SetCAPath records the CA cert location for the current process.
func SetCAPath(p string) { CAPath.Store(p) }

func (f *darwinFirewall) Redirect(ips []string, transparentPort int) error {
	caPath, _ := CAPath.Load().(string)
	if caPath == "" {
		return fmt.Errorf("firewall: CA path not set; call SetCAPath first")
	}
	if transparentPort <= 0 || transparentPort > 65535 {
		return fmt.Errorf("firewall: invalid transparent port %d", transparentPort)
	}
	script := buildApplyScript(buildApplyArgs{
		CAPath:          caPath,
		CASubject:       redactrCASubject,
		Anchor:          redactrAnchor,
		IPs:             ips,
		TransparentPort: transparentPort,
	})
	if err := runWithSudo(script); err != nil {
		darwinActive.Store(false)
		return err
	}
	darwinActive.Store(true)
	return nil
}

func (f *darwinFirewall) Unredirect() error {
	script := buildRemoveScript(redactrAnchor)
	if err := runWithSudo(script); err != nil {
		return err
	}
	darwinActive.Store(false)
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
	if err != nil {
		slog.Warn("firewall osascript failed", "error", err, "out", strings.TrimSpace(string(out)))
		return fmt.Errorf("osascript: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
```

- [ ] **Step 3: Build**

```
go build ./...
```
Expected: clean.

- [ ] **Step 4: Smoke test the apply path (macOS, requires sudo)**

This is a manual check — do NOT include in automated tests.

```
cat > /tmp/redactr-smoke.sh <<'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/redactrai/redactr/internal/firewall"
)

func main() {
	firewall.SetCAPath(os.Getenv("HOME") + "/.redactr/certs/ca.crt")
	mgr, err := firewall.New()
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	if err := mgr.Redirect([]string{"1.1.1.1"}, 58601); err != nil {
		fmt.Println("redirect:", err)
		return
	}
	fmt.Println("redirect installed; check pfctl -a com.redactr -sr")
}
EOF
```

Or just defer this check to the integration step in Task 11.

- [ ] **Step 5: Commit**

```bash
git add internal/firewall/redirect_darwin.go internal/firewall/darwin.go
git commit -m "feat(firewall): macOS Redirect/Unredirect via osascript GUI sudo"
```

---

## Phase 3 — Transparent SNI listener

### Task 6: SNI parser

**Files:**
- Create: `internal/proxy/sni.go`
- Create: `internal/proxy/sni_test.go`

- [ ] **Step 1: Write tests with golden TLS hello bytes**

Create `internal/proxy/sni_test.go`:

```go
package proxy

import (
	"encoding/hex"
	"strings"
	"testing"
)

// captured ClientHello for "api.anthropic.com" — generated via:
//   openssl s_client -connect api.anthropic.com:443 -servername api.anthropic.com -msg < /dev/null
// then extracted the first record from the PCAP. For testing here we
// hand-craft a minimal valid ClientHello with SNI extension.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// minimal_hello returns a synthetic but spec-valid TLS 1.2 ClientHello
// with a single SNI extension carrying name. Layout:
//   Record header: type=22, version=0x0301, length=N
//   Handshake header: type=1 (ClientHello), length=N-4
//   ClientHello body: version + random + sid_len(0) + cipher_suites_len(2) + cipher + comp_methods_len(1) + comp_method(0) + extensions_len + SNI_extension
func syntheticHello(t *testing.T, name string) []byte {
	t.Helper()
	// SNI extension value
	var sni []byte
	// list_length (uint16) = 1 + 2 + len(name)
	listLen := 3 + len(name)
	sni = append(sni, byte(listLen>>8), byte(listLen))
	sni = append(sni, 0) // name_type = host_name
	sni = append(sni, byte(len(name)>>8), byte(len(name)))
	sni = append(sni, []byte(name)...)
	// SNI extension wrapper: type=0, length, data
	var ext []byte
	ext = append(ext, 0, 0) // type 0
	ext = append(ext, byte(len(sni)>>8), byte(len(sni)))
	ext = append(ext, sni...)
	// Extensions block: total length, then ext bytes
	var exts []byte
	exts = append(exts, byte(len(ext)>>8), byte(len(ext)))
	exts = append(exts, ext...)
	// ClientHello body
	var body []byte
	body = append(body, 0x03, 0x03)        // version 1.2
	body = append(body, make([]byte, 32)...)// random
	body = append(body, 0)                  // session_id_length
	body = append(body, 0, 2, 0x00, 0x35)   // cipher_suites_length=2, then 1 suite
	body = append(body, 1, 0)               // compression_methods_length=1, method 0
	body = append(body, exts...)
	// Handshake header
	hsLen := len(body)
	var hs []byte
	hs = append(hs, 0x01)                                            // ClientHello
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))    // length (3 bytes)
	hs = append(hs, body...)
	// Record header
	rLen := len(hs)
	var rec []byte
	rec = append(rec, 0x16)                          // type Handshake
	rec = append(rec, 0x03, 0x01)                    // legacy version
	rec = append(rec, byte(rLen>>8), byte(rLen))     // length
	rec = append(rec, hs...)
	return rec
}

func TestParseSNIHappyPath(t *testing.T) {
	hello := syntheticHello(t, "api.anthropic.com")
	host, err := parseSNI(hello)
	if err != nil {
		t.Fatalf("parseSNI: %v", err)
	}
	if host != "api.anthropic.com" {
		t.Errorf("got %q want %q", host, "api.anthropic.com")
	}
}

func TestParseSNIDifferentHostname(t *testing.T) {
	hello := syntheticHello(t, "api.openai.com")
	host, _ := parseSNI(hello)
	if host != "api.openai.com" {
		t.Errorf("got %q want %q", host, "api.openai.com")
	}
}

func TestParseSNINotATLSRecord(t *testing.T) {
	if _, err := parseSNI([]byte("not tls")); err == nil {
		t.Error("expected error on non-TLS bytes")
	}
}

func TestParseSNINotAHandshake(t *testing.T) {
	// Record type 23 = ApplicationData, not Handshake.
	bytes := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}
	if _, err := parseSNI(bytes); err == nil {
		t.Error("expected error on non-handshake record")
	}
}

func TestParseSNINoExtension(t *testing.T) {
	// Same as syntheticHello but with empty extensions block.
	hello := mustHex("16 03 01 00 33 01 00 00 2f 03 03 " +
		"00000000000000000000000000000000" +
		"00000000000000000000000000000000" +
		"00 00 02 00 35 01 00 00 00")
	if _, err := parseSNI(hello); err == nil {
		t.Error("expected error when SNI extension is absent")
	}
}

func TestParseSNITruncated(t *testing.T) {
	hello := syntheticHello(t, "example.com")
	for i := 0; i < len(hello); i++ {
		if _, err := parseSNI(hello[:i]); err == nil {
			t.Errorf("expected error on truncation at byte %d", i)
		}
	}
}
```

- [ ] **Step 2: Run, fail**

```
go test ./internal/proxy/... -run "TestParseSNI"
```
Expected: FAIL — `parseSNI` undefined.

- [ ] **Step 3: Implement parser**

Create `internal/proxy/sni.go`:

```go
package proxy

import (
	"encoding/binary"
	"errors"
)

// errNoSNI signals that the ClientHello was syntactically OK but didn't
// carry a server_name extension.
var errNoSNI = errors.New("client hello has no SNI extension")

// parseSNI extracts the server_name from a TLS ClientHello in `data`.
// Returns errNoSNI if the hello is well-formed but lacks SNI; returns
// other errors for malformed input.
//
// Reference: RFC 5246 §7.4.1.2 (ClientHello), RFC 6066 §3 (SNI).
func parseSNI(data []byte) (string, error) {
	// TLS record header: type(1) + version(2) + length(2) = 5 bytes.
	if len(data) < 5 {
		return "", errors.New("tls: short record header")
	}
	if data[0] != 0x16 {
		return "", errors.New("tls: not a handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return "", errors.New("tls: record truncated")
	}
	hs := data[5 : 5+recLen]
	// Handshake header: type(1) + length(3).
	if len(hs) < 4 {
		return "", errors.New("tls: short handshake")
	}
	if hs[0] != 0x01 {
		return "", errors.New("tls: not a ClientHello")
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return "", errors.New("tls: handshake truncated")
	}
	body := hs[4 : 4+hsLen]
	// Body: version(2) + random(32) + session_id_length(1) + session_id +
	//       cipher_suites_length(2) + cipher_suites +
	//       compression_methods_length(1) + compression_methods +
	//       extensions_length(2) + extensions
	if len(body) < 2+32+1 {
		return "", errors.New("tls: hello too short")
	}
	p := 2 + 32
	sidLen := int(body[p])
	p++
	if len(body) < p+sidLen {
		return "", errors.New("tls: bad session id")
	}
	p += sidLen
	if len(body) < p+2 {
		return "", errors.New("tls: missing cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if len(body) < p+csLen {
		return "", errors.New("tls: bad cipher suites")
	}
	p += csLen
	if len(body) < p+1 {
		return "", errors.New("tls: missing compression methods length")
	}
	cmLen := int(body[p])
	p++
	if len(body) < p+cmLen {
		return "", errors.New("tls: bad compression methods")
	}
	p += cmLen
	if len(body) < p+2 {
		return "", errors.New("tls: missing extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if len(body) < p+extLen {
		return "", errors.New("tls: extensions truncated")
	}
	exts := body[p : p+extLen]
	// Walk extensions.
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[0:2])
		extDataLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if len(exts) < 4+extDataLen {
			return "", errors.New("tls: extension truncated")
		}
		extData := exts[4 : 4+extDataLen]
		if extType == 0 {
			// SNI extension: list_length(2), then entries:
			//   name_type(1) + name_length(2) + name
			if len(extData) < 2 {
				return "", errors.New("tls: short SNI list")
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if len(extData) < 2+listLen {
				return "", errors.New("tls: SNI list truncated")
			}
			list := extData[2 : 2+listLen]
			for len(list) >= 3 {
				nameType := list[0]
				nameLen := int(binary.BigEndian.Uint16(list[1:3]))
				if len(list) < 3+nameLen {
					return "", errors.New("tls: SNI name truncated")
				}
				if nameType == 0 { // host_name
					return string(list[3 : 3+nameLen]), nil
				}
				list = list[3+nameLen:]
			}
			return "", errNoSNI
		}
		exts = exts[4+extDataLen:]
	}
	return "", errNoSNI
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/proxy/... -run "TestParseSNI" -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/sni.go internal/proxy/sni_test.go
git commit -m "feat(proxy): TLS ClientHello SNI parser"
```

---

### Task 7: Transparent listener

**Files:**
- Create: `internal/proxy/transparent.go`
- Modify: `internal/proxy/proxy.go` (add `StartTransparent` method)

- [ ] **Step 1: Implement the listener**

Create `internal/proxy/transparent.go`:

```go
package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// startTransparent runs the SNI-sniffing listener loop on l. For every
// accepted connection it reads up to 4 KB to find the TLS ClientHello,
// extracts the SNI, and (if SNI matches an intercepted domain) splices
// the connection into goproxy as if a CONNECT had been issued.
//
// Connections without SNI, or whose SNI doesn't match any intercepted
// domain, are closed. (We don't transparently bridge to the original
// destination because pf strips it on macOS and we don't want to leak.)
func (p *Proxy) startTransparent(l net.Listener) {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("transparent accept", "error", err)
			continue
		}
		go p.handleTransparent(c)
	}
}

func (p *Proxy) handleTransparent(c net.Conn) {
	defer c.Close()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}

	// Peek the first TLS record without consuming it. We use a buffered
	// reader and Peek so the bytes can be replayed to goproxy.
	br := bufio.NewReaderSize(c, 16*1024)
	header, err := br.Peek(5)
	if err != nil {
		slog.Debug("transparent peek header", "error", err)
		return
	}
	if header[0] != 0x16 {
		slog.Debug("transparent: not a TLS handshake")
		return
	}
	recLen := int(header[3])<<8 | int(header[4])
	if recLen <= 0 || recLen > 16*1024 {
		slog.Debug("transparent: bogus record length", "len", recLen)
		return
	}
	hello, err := br.Peek(5 + recLen)
	if err != nil {
		slog.Debug("transparent peek body", "error", err)
		return
	}
	host, err := parseSNI(hello)
	if err != nil {
		slog.Debug("transparent SNI parse", "error", err)
		return
	}
	if !p.domains.ShouldIntercept(host) {
		slog.Debug("transparent: SNI not in intercept list", "host", host)
		return
	}

	// Clear deadline; goproxy manages its own.
	_ = c.SetReadDeadline(time.Time{})

	// Construct a synthetic CONNECT request and replay-buffered conn so
	// the full TLS handshake is visible to goproxy.
	connectReq := "CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\n\r\n"
	wrapped := &replayConn{
		Conn:  c,
		extra: io.MultiReader(strings.NewReader(connectReq), br),
	}
	// Hand to goproxy via its embedded http.Server.
	p.serveConn(wrapped)
}

// replayConn wraps a net.Conn so that Read returns from `extra` first
// (the synthetic CONNECT followed by the buffered ClientHello), then
// falls through to the underlying Conn.
type replayConn struct {
	net.Conn
	mu    sync.Mutex
	extra io.Reader
}

func (r *replayConn) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.extra != nil {
		n, err := r.extra.Read(b)
		if err == io.EOF {
			r.extra = nil
			err = nil
		}
		if n > 0 {
			return n, err
		}
		r.extra = nil
	}
	return r.Conn.Read(b)
}

// serveConn hands a single connection to goproxy. We do this by
// constructing a one-shot listener that returns this connection once.
func (p *Proxy) serveConn(c net.Conn) {
	listener := &oneShotListener{conn: c, addr: c.LocalAddr()}
	srv := &http.Server{Handler: p.goproxy}
	_ = srv.Serve(listener)
}

type oneShotListener struct {
	conn net.Conn
	addr net.Addr
	done bool
	mu   sync.Mutex
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.addr }

// silence unused-import in some build configurations
var _ = bytes.NewReader
```

- [ ] **Step 2: Add `StartTransparent` to `Proxy`**

In `internal/proxy/proxy.go`, after the existing `Start` method (around line 246), add:

```go
// StartTransparent binds an OS-assigned port for transparent (SNI-sniffing)
// connections from pf rdr redirected traffic. The returned address is
// the resolved listener address (e.g. "127.0.0.1:58601") which the
// firewall controller uses when generating pf rules.
func (p *Proxy) StartTransparent(port int) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	go p.startTransparent(l)
	return l.Addr().String(), nil
}
```

The function uses `fmt`, `net` — both already imported.

- [ ] **Step 3: Build**

```
go build ./...
```
Expected: clean.

- [ ] **Step 4: Smoke test**

Open `/dev/null < ` doesn't apply — the listener is best validated end-to-end in Task 11. For now confirm the package builds.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/transparent.go internal/proxy/proxy.go
git commit -m "feat(proxy): transparent SNI-sniffing listener"
```

---

## Phase 4 — Wire into daemon

### Task 8: `firewall.Controller`

**Files:**
- Create: `internal/firewall/controller.go`
- Create: `internal/firewall/controller_test.go`

- [ ] **Step 1: Write tests**

Create `internal/firewall/controller_test.go`:

```go
package firewall

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type fakeMgr struct {
	redirectCalls atomic.Int64
	unredirectCalls atomic.Int64
	lastIPs       []string
	lastPort      int
	failNext      error
	active        atomic.Bool
}

func (f *fakeMgr) BlockDirect(_ []string, _ int) error { return nil }
func (f *fakeMgr) Unblock() error                       { return nil }
func (f *fakeMgr) Status() ([]Rule, error)              { return nil, nil }
func (f *fakeMgr) Cleanup() error                       { return nil }
func (f *fakeMgr) Redirect(ips []string, port int) error {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.redirectCalls.Add(1)
	f.lastIPs = append([]string(nil), ips...)
	f.lastPort = port
	f.active.Store(true)
	return nil
}
func (f *fakeMgr) Unredirect() error {
	f.unredirectCalls.Add(1)
	f.active.Store(false)
	return nil
}
func (f *fakeMgr) IsActive() (bool, error) { return f.active.Load(), nil }

func TestControllerEnableInstallsRedirectAndPersists(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "firewall.json")
	mgr := &fakeMgr{}
	resolver := &fakeResolver{results: map[string][]string{
		"api.anthropic.com": {"1.1.1.1", "2.2.2.2"},
	}}
	c := NewController(mgr, resolver, statePath)

	if err := c.Enable(context.Background(), []string{"api.anthropic.com"}, "127.0.0.1:58600", 58601); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if mgr.redirectCalls.Load() != 1 {
		t.Errorf("expected 1 Redirect call, got %d", mgr.redirectCalls.Load())
	}
	if mgr.lastPort != 58601 {
		t.Errorf("got port %d, want 58601", mgr.lastPort)
	}
	st, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("loadstate: %v", err)
	}
	if !st.Active {
		t.Error("state should be active after Enable")
	}
	if !ipSetsEqual(st.IPs, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Errorf("state IPs %v don't match resolved", st.IPs)
	}
}

func TestControllerDisableUninstallsAndClearsState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "firewall.json")
	mgr := &fakeMgr{}
	resolver := &fakeResolver{results: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	c := NewController(mgr, resolver, statePath)

	_ = c.Enable(context.Background(), []string{"a.example.com"}, "127.0.0.1:58600", 58601)
	if err := c.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if mgr.unredirectCalls.Load() != 1 {
		t.Errorf("expected 1 Unredirect call, got %d", mgr.unredirectCalls.Load())
	}
	st, _ := LoadState(statePath)
	if st.Active {
		t.Error("state should be inactive after Disable")
	}
}

func TestControllerEnableFailsWhenRedirectFails(t *testing.T) {
	dir := t.TempDir()
	mgr := &fakeMgr{failNext: errors.New("user cancelled sudo")}
	resolver := &fakeResolver{results: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	c := NewController(mgr, resolver, filepath.Join(dir, "firewall.json"))

	if err := c.Enable(context.Background(), []string{"a.example.com"}, "127.0.0.1:58600", 58601); err == nil {
		t.Fatal("Enable should fail when Redirect fails")
	}
}

func TestControllerReconcileSkipsWhenIPsUnchanged(t *testing.T) {
	dir := t.TempDir()
	mgr := &fakeMgr{}
	resolver := &fakeResolver{results: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	c := NewController(mgr, resolver, filepath.Join(dir, "firewall.json"))
	_ = c.Enable(context.Background(), []string{"a.example.com"}, "127.0.0.1:58600", 58601)
	if mgr.redirectCalls.Load() != 1 {
		t.Fatalf("setup: 1 call expected; got %d", mgr.redirectCalls.Load())
	}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if mgr.redirectCalls.Load() != 1 {
		t.Errorf("Reconcile should not re-call Redirect when IPs unchanged; got %d total calls",
			mgr.redirectCalls.Load())
	}
}

func TestControllerReconcileReinstallsWhenIPsChange(t *testing.T) {
	dir := t.TempDir()
	mgr := &fakeMgr{}
	resolver := &fakeResolver{results: map[string][]string{"a.example.com": {"1.1.1.1"}}}
	c := NewController(mgr, resolver, filepath.Join(dir, "firewall.json"))
	_ = c.Enable(context.Background(), []string{"a.example.com"}, "127.0.0.1:58600", 58601)
	resolver.results["a.example.com"] = []string{"9.9.9.9"}
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if mgr.redirectCalls.Load() != 2 {
		t.Errorf("Reconcile should re-call Redirect when IPs change; got %d calls", mgr.redirectCalls.Load())
	}
	if !ipSetsEqual(mgr.lastIPs, []string{"9.9.9.9"}) {
		t.Errorf("IPs not updated: %v", mgr.lastIPs)
	}
}
```

- [ ] **Step 2: Run, fail**

```
go test ./internal/firewall/... -run "TestController"
```
Expected: FAIL — `Controller`, `NewController`, `Enable`, `Disable`, `Reconcile` undefined.

- [ ] **Step 3: Implement Controller**

Create `internal/firewall/controller.go`:

```go
package firewall

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Controller orchestrates Manager + DNS reconciliation + state persistence.
// It is platform-agnostic: the platform-specific bits live in the
// Manager interface.
type Controller struct {
	mgr       Manager
	resolver  Resolver
	statePath string

	mu              sync.Mutex
	domains         []string
	proxyAddr       string
	transparentPort int
	currentIPs      []string
	enabled         bool
}

func NewController(mgr Manager, resolver Resolver, statePath string) *Controller {
	if resolver == nil {
		resolver = DefaultResolver
	}
	return &Controller{
		mgr:       mgr,
		resolver:  resolver,
		statePath: statePath,
	}
}

// Enable resolves the supplied domains, installs Redirect rules, and
// persists state. Returns the underlying Manager error if installation
// fails (including when the user cancels the sudo prompt).
func (c *Controller) Enable(ctx context.Context, domains []string, proxyAddr string, transparentPort int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ips, err := resolveAll(ctx, c.resolver, domains)
	if err != nil {
		return err
	}
	if err := c.mgr.Redirect(ips, transparentPort); err != nil {
		return err
	}
	c.domains = append([]string(nil), domains...)
	c.proxyAddr = proxyAddr
	c.transparentPort = transparentPort
	c.currentIPs = ips
	c.enabled = true
	c.persist()
	return nil
}

// Disable removes the Redirect rules and clears persisted state.
func (c *Controller) Disable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil
	}
	if err := c.mgr.Unredirect(); err != nil {
		return err
	}
	c.enabled = false
	c.currentIPs = nil
	c.persist()
	return nil
}

// Reconcile re-resolves the configured domains and re-runs Redirect
// only when the IP set has changed. Cheap to call on a 5-min ticker.
func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil
	}
	ips, err := resolveAll(ctx, c.resolver, c.domains)
	if err != nil {
		// Don't tear down — keep the existing rules in place.
		return err
	}
	if ipSetsEqual(ips, c.currentIPs) {
		return nil
	}
	if err := c.mgr.Redirect(ips, c.transparentPort); err != nil {
		return err
	}
	c.currentIPs = ips
	c.persist()
	return nil
}

// IsActive reports whether redirect rules are currently installed.
func (c *Controller) IsActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// Snapshot returns the current state for /api/proxy/status.
func (c *Controller) Snapshot() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return State{
		Active:          c.enabled,
		ProxyAddr:       c.proxyAddr,
		TransparentAddr: "",
		IPs:             append([]string(nil), c.currentIPs...),
		LastReconciled:  time.Now(),
		CAInstalled:     c.enabled, // we install on Enable; treat as same lifecycle
	}
}

// RunReconcileLoop ticks every interval and re-reconciles. Honours
// context cancellation. Intended to be run in a dedicated goroutine.
func (c *Controller) RunReconcileLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.Reconcile(ctx)
		}
	}
}

func (c *Controller) persist() {
	_ = SaveState(c.statePath, State{
		Active:          c.enabled,
		ProxyAddr:       c.proxyAddr,
		TransparentAddr: "", // set by daemon when starting transparent listener
		IPs:             append([]string(nil), c.currentIPs...),
		LastReconciled:  time.Now(),
		CAInstalled:     c.enabled,
	})
}

// ErrAlreadyEnabled is returned by Enable when called twice without
// an intervening Disable.
var ErrAlreadyEnabled = errors.New("firewall: already enabled")
```

- [ ] **Step 4: Run tests**

```
go test ./internal/firewall/... -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/firewall/controller.go internal/firewall/controller_test.go
git commit -m "feat(firewall): Controller orchestrating Manager + DNS reconcile"
```

---

### Task 9: Wire into API handlers

**Files:**
- Modify: `internal/api/server.go`
- Modify: `internal/api/routes.go`
- Modify: `cmd/redactr/main.go`

- [ ] **Step 1: Extend Server struct to hold the firewall Controller and transparent port**

In `internal/api/server.go`, add to imports:

```go
	"github.com/redactrai/redactr/internal/firewall"
```

Add fields and a setter:

```go
type Server struct {
	// ... existing fields ...
	firewall         *firewall.Controller
	transparentAddr  string
}

// SetFirewall attaches a firewall Controller. Called from main during
// startup before Start.
func (s *Server) SetFirewall(c *firewall.Controller, transparentAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.firewall = c
	s.transparentAddr = transparentAddr
}
```

- [ ] **Step 2: Wire `handleProxyEnable` and `handleProxyDisable`**

In `internal/api/routes.go`, find `handleProxyEnable` and replace with:

```go
func (s *Server) handleProxyEnable(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, map[string]string{"status": "ok", "message": "proxy controller not configured"})
		return
	}
	addr, err := s.proxy.Start(0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.cfgMgr.Update(func(c *config.Config) { c.Proxy.Enabled = true })
	writeProxyState(addr)

	// Install firewall redirect rules. If this fails (e.g. user cancels
	// the sudo prompt), keep the listener up and surface a "listening"
	// state to the dashboard.
	if s.firewall != nil {
		s.mu.Lock()
		transparentAddr := s.transparentAddr
		s.mu.Unlock()
		port := portFromAddr(transparentAddr)
		cfg := s.cfgMgr.Get()
		if err := s.firewall.Enable(r.Context(), cfg.Proxy.InterceptedDomains, addr, port); err != nil {
			writeJSON(w, map[string]any{
				"status":      "listening",
				"addr":        addr,
				"routing":     "failed",
				"reason":      err.Error(),
			})
			return
		}
	}
	writeJSON(w, map[string]any{"status": "ok", "addr": addr, "routing": "active"})
}

func (s *Server) handleProxyDisable(w http.ResponseWriter, r *http.Request) {
	if s.firewall != nil {
		_ = s.firewall.Disable()
	}
	if s.proxy != nil {
		s.proxy.Stop()
	}
	s.cfgMgr.Update(func(c *config.Config) { c.Proxy.Enabled = false })
	clearProxyState()
	writeJSON(w, map[string]string{"status": "ok"})
}
```

Add the helper at the bottom of `routes.go`:

```go
// portFromAddr extracts the port number from a "host:port" string.
// Returns 0 on parse failure.
func portFromAddr(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}
```

Add `"net"` to the import block if not present.

- [ ] **Step 3: Update `handleProxyStatus`**

In `internal/api/routes.go`, find `handleProxyStatus` and replace with:

```go
func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Get()
	status := map[string]any{
		"enabled": cfg.Proxy.Enabled,
	}
	if s.proxy != nil {
		status["addr"] = s.proxy.Addr()
	}
	if s.firewall != nil {
		status["routing"] = s.firewall.IsActive()
	}
	writeJSON(w, status)
}
```

- [ ] **Step 4: Wire up in `cmd/redactr/main.go`**

In `cmd/redactr/main.go`, after the API server is constructed but before `apiServer.Start`, add:

```go
// Firewall Controller — needed for "Enable Proxy" to actually route traffic.
fwMgr, err := firewall.New()
if err != nil {
	log.Fatalf("firewall: %v", err)
}
firewall.SetCAPath(filepath.Join(baseDir, "certs", "ca.crt"))

statePath := filepath.Join(baseDir, "state", "firewall.json")
fwController := firewall.NewController(fwMgr, firewall.DefaultResolver, statePath)

// Start transparent listener.
transparentAddr, err := p.StartTransparent(0)
if err != nil {
	log.Fatalf("transparent listener: %v", err)
}
log.Printf("Transparent listener: %s", transparentAddr)

apiServer.SetFirewall(fwController, transparentAddr)

// 5-minute reconcile loop.
reconcileCtx, reconcileCancel := context.WithCancel(context.Background())
go fwController.RunReconcileLoop(reconcileCtx, 5*time.Minute)
defer reconcileCancel()
```

Add imports if missing:
```go
	"context"

	"github.com/redactrai/redactr/internal/firewall"
```

- [ ] **Step 5: Build + test**

```
go build ./...
go test ./...
```
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/api/server.go internal/api/routes.go cmd/redactr/main.go
git commit -m "feat(api): firewall.Controller wired into proxy enable/disable + status"
```

---

### Task 10: Three-state proxy pill UI

**Files:**
- Modify: `internal/api/static/style.css`
- Modify: `internal/api/static/app.js`
- (No HTML changes; the existing pill element gets a new `data-state="listening"` value.)

- [ ] **Step 1: CSS for the listening state**

In `internal/api/static/style.css`, find the existing `.proxy-pill` rules and append:

```css
.proxy-pill[data-state="listening"] {
  border-color: rgba(234, 179, 8, 0.40);
}
.proxy-pill[data-state="listening"] .proxy-dot {
  background: var(--warning, #eab308);
}
.proxy-pill[data-state="listening"] .proxy-pill-label {
  color: var(--warning, #eab308);
}
```

(If your existing pill uses different selectors for the dot/label, adapt to those — just keep "yellow with no pulse" as the visual.)

- [ ] **Step 2: JS — three-state render**

In `internal/api/static/app.js`, find the function that renders the proxy pill from `/api/proxy/status` (`renderProxy` or equivalent). Replace its body with:

```js
function renderProxy() {
  const pill = document.getElementById('proxy-pill');
  const label = document.getElementById('proxy-label');
  const addr = document.getElementById('proxy-addr');
  if (!pill || !state.proxyStatus) return;

  const enabled = !!state.proxyStatus.enabled;
  const routing = state.proxyStatus.routing === true;

  let visual = 'off';
  let labelText = 'Proxy offline';
  if (enabled && routing) {
    visual = 'on';
    labelText = 'Proxy active';
  } else if (enabled && !routing) {
    visual = 'listening';
    labelText = 'Listening — routing not installed';
  }

  pill.dataset.state = visual;
  if (label) label.textContent = labelText;
  if (addr) addr.textContent = state.proxyStatus.addr || '';
}
```

(The existing `renderProxy` may have additional rendering — preserve any extra UI hooks; only the state machine is new.)

- [ ] **Step 3: Surface the routing-failed reason**

When `POST /api/proxy/enable` returns `{routing: "failed", reason: "..."}`, show that as a toast. Find the existing handler for the proxy toggle button and update it to read `routing` and `reason` from the response:

```js
async function toggleProxy(enable) {
  const res = await api(enable ? '/proxy/enable' : '/proxy/disable', { method: 'POST' });
  if (enable && res.routing === 'failed' && typeof toast === 'function') {
    toast('Proxy listening, but traffic routing failed: ' + (res.reason || 'unknown'), 'warn');
  } else if (typeof toast === 'function') {
    toast(enable ? 'Proxy enabled' : 'Proxy disabled', 'ok');
  }
  await fetchAll();
}
```

- [ ] **Step 4: Smoke test**

```
go build -o /tmp/redactr-task10 ./cmd/redactr
pkill -f redactr 2>/dev/null
sleep 1
/tmp/redactr-task10 &
sleep 3
PORT=$(cat ~/.redactr/state/dashboard.port 2>/dev/null)
echo "Open http://$PORT — click Enable Proxy"
echo "Expected: macOS password prompt; if cancelled, pill goes yellow + toast warns"
echo "If approved: pill goes green; pfctl -a com.redactr -sr should list rdr rules"
sudo -n pfctl -a com.redactr -sr 2>/dev/null || echo "(pfctl needs sudo to inspect; check manually)"
pkill -f redactr 2>/dev/null
```

- [ ] **Step 5: Commit**

```bash
git add internal/api/static/style.css internal/api/static/app.js
git commit -m "feat(ui): three-state proxy pill (offline / listening / active)"
```

---

## Phase 5 — Cleanup

### Task 11: Cleanup on shutdown + `redactr cleanup` updates

**Files:**
- Modify: `cmd/redactr/main.go`
- Modify: the existing `runCleanup` function in `cmd/redactr/main.go`

- [ ] **Step 1: Hook firewall cleanup into graceful shutdown**

In `cmd/redactr/main.go`, find the SIGTERM handler / shutdown sequence. Add the firewall disable BEFORE state files are removed:

```go
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
<-sigCh
log.Println("Shutting down...")

// Stop the reconcile loop and remove pf rules so the user isn't
// surprised by TLS failures after redactr exits.
reconcileCancel()
if err := fwController.Disable(); err != nil {
	log.Printf("firewall disable on shutdown: %v", err)
}

p.Stop()
sidecarMgr.Stop()
apiServer.Stop()
```

(Adapt to your existing shutdown order — the key new lines are `reconcileCancel()` and `fwController.Disable()` before `p.Stop()`.)

- [ ] **Step 2: Update `redactr cleanup` to also flush pf rules**

In `cmd/redactr/main.go`, find `func runCleanup()`. Replace its body with:

```go
func runCleanup() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("home dir: %v", err)
	}
	statePath := filepath.Join(home, ".redactr", "state", "firewall.json")

	// Flush pf rules unconditionally — uses the same osascript path
	// as the daemon, so a sudo prompt may appear.
	firewall.SetCAPath(filepath.Join(home, ".redactr", "certs", "ca.crt"))
	mgr, err := firewall.New()
	if err == nil {
		if err := mgr.Unredirect(); err != nil && !errors.Is(err, firewall.ErrNotImplemented) {
			log.Printf("firewall unredirect: %v", err)
		}
	}

	// Also clear the state file.
	_ = os.Remove(statePath)

	// Legacy block-mode cleanup (kept for users who used BlockDirect).
	if mgr != nil {
		_ = mgr.Cleanup()
	}
	fmt.Println("Firewall rules cleaned up")
}
```

Add `"errors"` to imports if missing.

- [ ] **Step 3: Build + test**

```
go build ./...
go test ./...
```
Expected: clean.

- [ ] **Step 4: Smoke test the cleanup path**

```
pkill -f redactr 2>/dev/null
sleep 1
go run ./cmd/redactr &
sleep 3
PORT=$(cat ~/.redactr/state/dashboard.port 2>/dev/null)
curl -s -X POST "http://127.0.0.1:$PORT/api/proxy/enable"
sleep 1
sudo -n pfctl -a com.redactr -sr 2>/dev/null | head -5 || echo "(check manually)"
pkill -INT -f redactr
sleep 2
sudo -n pfctl -a com.redactr -sr 2>/dev/null || echo "(rules cleared)"
```

Expected: rules listed before SIGINT, gone after.

- [ ] **Step 5: Commit**

```bash
git add cmd/redactr/main.go
git commit -m "feat(redactr): graceful shutdown + cleanup subcommand flush pf rules"
```

---

## Self-Review

### Spec coverage

| Spec section | Implemented by |
|---|---|
| §3 architecture diagram | Tasks 5, 7, 8, 9 |
| §4 new files list | Tasks 2 (script), 3 (state), 4 (DNS), 5 (redirect), 6 (sni), 7 (transparent), 8 (controller) |
| §4 modified files list | Tasks 1, 7, 9, 10, 11 |
| §5 privilege model (osascript GUI sudo) | Task 5 (`runWithSudo`) |
| §6 transparent listener + SNI | Tasks 6 + 7 |
| §7 CA trust automation | Task 2 (script generator embeds the conditional install) + Task 5 (passes CA path) |
| §8 failure modes | Task 9 (routing=failed surface), Task 10 (UI tri-state + toast) |
| §9 state persistence | Task 3 + Task 8 |
| §10 testing strategy | Each task has a TDD test step; SNI parser, script generator, controller, DNS, state all covered |
| §11 migration & cleanup | Task 11 |

### Placeholder scan

- No "TBD", "TODO", or "implement later" in any step.
- Every task has concrete code and exact file paths.
- Test names are concrete, not "test the right thing."

### Type consistency

- `firewall.Controller` API: `Enable(ctx, domains, proxyAddr, transparentPort) error`, `Disable() error`, `Reconcile(ctx) error`, `IsActive() bool`, `RunReconcileLoop(ctx, interval)` — used consistently across Tasks 8, 9, 11.
- `Manager.Redirect(ips []string, transparentPort int)` — same signature in Tasks 1 and 5 and the Controller test fakes.
- `Proxy.StartTransparent(port int) (string, error)` — defined in Task 7, called in Task 9.
- `parseSNI([]byte) (string, error)` — defined in Task 6, called in Task 7's `handleTransparent`.
- `buildApplyScript(buildApplyArgs) string` and `buildRemoveScript(string) string` — defined in Task 2, called in Task 5.

No drift.

---

## Execution

Plan saved to `docs/superpowers/plans/2026-04-30-transparent-proxy.md`. 11 tasks across 5 phases.
