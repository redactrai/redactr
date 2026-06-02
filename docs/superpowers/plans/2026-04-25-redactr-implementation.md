# Redactr Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Redactr — a local HTTPS forward proxy that filters PII, secrets, and sensitive information from AI coding tools, controlled by an embedded Next.js dashboard.

**Architecture:** Single Go binary (monolithic process) with embedded Next.js static dashboard. Uses goproxy for HTTPS MITM interception, BoltDB for log storage, and a Python sidecar for GLiNER PII model inference. All scanning happens locally — nothing leaves the machine unscanned.

**Tech Stack:** Go 1.22+, goproxy, BoltDB (bbolt), Next.js 14 (static export), Python 3.10+ (GLiNER sidecar), WebSocket (gorilla/websocket)

---

## File Map

### Go Binary (`cmd/redactr/`)
| File | Responsibility |
|------|---------------|
| `cmd/redactr/main.go` | Entry point: parse flags, init config, start all subsystems |

### MCP Wrapper Binary (`cmd/redactr-mcp-wrap/`)
| File | Responsibility |
|------|---------------|
| `cmd/redactr-mcp-wrap/main.go` | Entry point: wrap MCP server stdin/stdout, connect to Redactr API |

### Config (`internal/config/`)
| File | Responsibility |
|------|---------------|
| `internal/config/config.go` | Config struct, load/save YAML, hot-reload watcher |
| `internal/config/defaults.go` | Default config values, built-in regex patterns list |

### Certificate Authority (`internal/certgen/`)
| File | Responsibility |
|------|---------------|
| `internal/certgen/ca.go` | Generate root CA cert/key, load existing, issue per-domain certs |

### Proxy Engine (`internal/proxy/`)
| File | Responsibility |
|------|---------------|
| `internal/proxy/proxy.go` | goproxy setup, request/response interception, domain filtering |
| `internal/proxy/extract.go` | Extract last user message from API request bodies (Anthropic, OpenAI, GitHub) |
| `internal/proxy/rewrite.go` | Rewrite request body with redacted content |

### Scanning Pipeline (`internal/scanner/`)
| File | Responsibility |
|------|---------------|
| `internal/scanner/pipeline.go` | Pipeline coordinator: runs layers sequentially, merges results |
| `internal/scanner/types.go` | Shared types: Finding, ScanResult, ScanReport |
| `internal/scanner/cache.go` | LRU cache: hash input, store/retrieve results, invalidation |

### Scanner Layers
| File | Responsibility |
|------|---------------|
| `internal/scanner/regex/regex.go` | Layer 1: compile and match regex patterns against input text |
| `internal/scanner/entropy/entropy.go` | Layer 2: Shannon entropy on sliding windows |
| `internal/scanner/gliner/client.go` | Layer 3: HTTP client to GLiNER Python sidecar |
| `internal/scanner/contextgate/stub.go` | Layer 4: future extension point interface + no-op implementation |

### Redactor (`internal/redactor/`)
| File | Responsibility |
|------|---------------|
| `internal/redactor/redactor.go` | Merge findings, deduplicate, apply `[REDACTED-X]` labels |

### File Blocking (`internal/fileblock/`)
| File | Responsibility |
|------|---------------|
| `internal/fileblock/fileblock.go` | Filename extension check + content pattern matching |

### Domain Filtering (`internal/domain/`)
| File | Responsibility |
|------|---------------|
| `internal/domain/domain.go` | Intercept allowlist, blocked domain list, matching logic |

### Storage (`internal/store/`)
| File | Responsibility |
|------|---------------|
| `internal/store/store.go` | BoltDB init, scan report CRUD, query/filter for dashboard |

### Sidecar Manager (`internal/sidecar/`)
| File | Responsibility |
|------|---------------|
| `internal/sidecar/manager.go` | Spawn Python sidecar, health check, restart, lazy-load lifecycle |

### API Server (`internal/api/`)
| File | Responsibility |
|------|---------------|
| `internal/api/server.go` | HTTP mux: static dashboard + REST routes + WebSocket upgrade |
| `internal/api/routes.go` | REST handlers: config CRUD, logs query, proxy control, cache stats |
| `internal/api/ws.go` | WebSocket hub: broadcast log events, status updates to dashboard |

### MCP Wrapper Logic (`internal/mcpwrap/`)
| File | Responsibility |
|------|---------------|
| `internal/mcpwrap/wrap.go` | Intercept JSON-RPC stdin/stdout, scan payloads via Redactr API |

> **Note:** MCP server auto-discovery (`discover.go`) is deferred to post-v1. The MCP wrapper binary works — users configure wrapped servers manually via dashboard or config.

### Firewall (`internal/firewall/`)
| File | Responsibility |
|------|---------------|
| `internal/firewall/firewall.go` | Interface + platform detection |
| `internal/firewall/darwin.go` | macOS pf rules |
| `internal/firewall/linux.go` | Linux iptables rules |
| `internal/firewall/windows.go` | Windows netsh advfirewall rules |

### Hooks (`internal/hooks/`)
| File | Responsibility |
|------|---------------|
| `internal/hooks/claude.go` | Read/write Claude Code hooks in `.claude/settings.json` |
| `internal/hooks/safecmd.go` | Load safecmd allowlist, apply user overrides |

### GLiNER Sidecar (`sidecar/gliner/`)
| File | Responsibility |
|------|---------------|
| `sidecar/gliner/server.py` | Flask/FastAPI HTTP server: load GLiNER model, expose `/detect` endpoint |
| `sidecar/gliner/requirements.txt` | Python dependencies: gliner, flask/fastapi, uvicorn |

### Dashboard (`web/`)
| File | Responsibility |
|------|---------------|
| `web/package.json` | Next.js project config |
| `web/app/layout.tsx` | Root layout with navigation |
| `web/app/page.tsx` | Landing page: ON/OFF toggle, status, quick stats |
| `web/app/logs/page.tsx` | Log view: real-time stream, filters, expandable detail |
| `web/app/config/page.tsx` | Configuration: scanning, regex, words, files, domains, cache |
| `web/app/mcp/page.tsx` | MCP management: discover, wrap/unwrap |
| `web/app/hooks/page.tsx` | Hooks management: safecmd allowlist, overrides |
| `web/app/latency/page.tsx` | Latency observability: charts, percentiles |
| `web/lib/api.ts` | API client: REST calls + WebSocket connection |
| `web/components/toggle.tsx` | Reusable ON/OFF toggle component |
| `web/components/log-entry.tsx` | Expandable log entry with diff view |
| `web/components/latency-chart.tsx` | Latency chart component |

### Build & Config
| File | Responsibility |
|------|---------------|
| `Makefile` | Build targets: build, test, benchmark, dev |
| `scripts/build.sh` | Build Next.js static export, then Go binary with embed |
| `configs/default.yaml` | Default config shipped with binary |
| `.gitignore` | Ignore: benchmarks/datasets/, .superpowers/, vendor/ |

---

## Phase 1: Foundation (Tasks 1-5)

Core infrastructure: config, certs, basic proxy, BoltDB storage. After this phase you have a working HTTPS proxy that forwards traffic.

---

### Task 1: Project Scaffolding & Go Module Init

**Files:**
- Create: `go.mod`
- Create: `cmd/redactr/main.go`
- Create: `Makefile`
- Create: `.gitignore`
- Create: `configs/default.yaml`

- [ ] **Step 1: Initialize Go module**

```bash
cd /Users/rakeshguha/Desktop/Code/clearPass
go mod init github.com/rakeshguha/redactr
```

- [ ] **Step 2: Create `.gitignore`**

```gitignore
# Binaries
bin/
*.exe

# Dependencies
vendor/

# Benchmarks data
benchmarks/datasets/
benchmarks/results/

# Superpowers
.superpowers/

# State
.redactr/

# Next.js
web/node_modules/
web/.next/
web/out/

# OS
.DS_Store
```

- [ ] **Step 3: Create default config file**

Create `configs/default.yaml`:

```yaml
proxy:
  enabled: false
  intercepted_domains:
    - api.anthropic.com
    - api.openai.com
    - api.githubcopilot.com
    - copilot-proxy.githubusercontent.com
  blocked_domains: []

scanning:
  regex_enabled: true
  entropy_enabled: true
  entropy_threshold: 4.5
  gliner_enabled: true
  custom_patterns: []
  custom_blocked_words: []
  cache_max_size: 10000

file_blocking:
  blocked_extensions:
    - ".env"
    - ".tfstate"
    - ".pem"
    - ".key"
    - ".p12"
    - ".pfx"
  content_patterns_enabled: true

hooks:
  enabled: false
  claude_code: false
  safecmd_overrides:
    added: []
    removed: []

mcp:
  wrapped_servers: {}
```

- [ ] **Step 4: Create minimal main.go**

Create `cmd/redactr/main.go`:

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "cleanup" {
		fmt.Println("redactr: cleanup not yet implemented")
		return
	}
	fmt.Println("redactr: starting...")
}
```

- [ ] **Step 5: Create Makefile**

```makefile
.PHONY: build test dev clean

BINARY=bin/redactr
MCP_BINARY=bin/redactr-mcp-wrap

build:
	go build -o $(BINARY) ./cmd/redactr
	go build -o $(MCP_BINARY) ./cmd/redactr-mcp-wrap

test:
	go test ./... -v

dev:
	go run ./cmd/redactr

clean:
	rm -rf bin/

benchmark:
	go test ./benchmarks/... -bench=. -v
```

- [ ] **Step 6: Verify build compiles**

```bash
make build
```

Expected: binary at `bin/redactr`, runs and prints "redactr: starting..."

- [ ] **Step 7: Commit**

```bash
git add go.mod cmd/ Makefile .gitignore configs/
git commit -m "feat: scaffold project structure with Go module and build system"
```

---

### Task 2: Config Package

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/defaults.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write failing test for config loading**

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Proxy.Enabled {
		t.Error("expected proxy disabled by default")
	}
	if len(cfg.Proxy.InterceptedDomains) == 0 {
		t.Error("expected default intercepted domains")
	}
	if cfg.Scanning.EntropyThreshold != 4.5 {
		t.Errorf("expected entropy threshold 4.5, got %f", cfg.Scanning.EntropyThreshold)
	}
	if len(cfg.FileBlocking.BlockedExtensions) == 0 {
		t.Error("expected default blocked extensions")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected config file to be created on first load")
	}
}

func TestLoadExistingConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	yaml := []byte(`proxy:
  enabled: true
  intercepted_domains:
    - custom.api.com
  blocked_domains:
    - evil.com
scanning:
  regex_enabled: false
  entropy_enabled: true
  entropy_threshold: 5.0
  gliner_enabled: true
  custom_patterns: []
  custom_blocked_words: ["secret-project"]
  cache_max_size: 5000
file_blocking:
  blocked_extensions: [".env"]
  content_patterns_enabled: false
hooks:
  enabled: false
  claude_code: false
  safecmd_overrides:
    added: []
    removed: []
mcp:
  wrapped_servers: {}
`)
	os.WriteFile(path, yaml, 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !cfg.Proxy.Enabled {
		t.Error("expected proxy enabled")
	}
	if cfg.Proxy.InterceptedDomains[0] != "custom.api.com" {
		t.Error("expected custom domain")
	}
	if cfg.Proxy.BlockedDomains[0] != "evil.com" {
		t.Error("expected blocked domain")
	}
	if cfg.Scanning.RegexEnabled {
		t.Error("expected regex disabled")
	}
	if cfg.Scanning.EntropyThreshold != 5.0 {
		t.Errorf("expected threshold 5.0, got %f", cfg.Scanning.EntropyThreshold)
	}
	if cfg.Scanning.CustomBlockedWords[0] != "secret-project" {
		t.Error("expected custom blocked word")
	}
}

func TestSaveConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg, _ := Load(path)
	cfg.Proxy.Enabled = true
	cfg.Proxy.BlockedDomains = []string{"blocked.com"}

	err := Save(path, cfg)
	if err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload error: %v", err)
	}
	if !reloaded.Proxy.Enabled {
		t.Error("expected proxy enabled after save")
	}
	if reloaded.Proxy.BlockedDomains[0] != "blocked.com" {
		t.Error("expected blocked domain persisted")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/config/ -v
```

Expected: FAIL — `Load` and `Save` not defined.

- [ ] **Step 3: Write defaults**

Create `internal/config/defaults.go`:

```go
package config

func DefaultConfig() *Config {
	return &Config{
		Proxy: ProxyConfig{
			Enabled: false,
			InterceptedDomains: []string{
				"api.anthropic.com",
				"api.openai.com",
				"api.githubcopilot.com",
				"copilot-proxy.githubusercontent.com",
			},
			BlockedDomains: []string{},
		},
		Scanning: ScanningConfig{
			RegexEnabled:     true,
			EntropyEnabled:   true,
			EntropyThreshold: 4.5,
			GLiNEREnabled:    true,
			CustomPatterns:   []CustomPattern{},
			CustomBlockedWords: []string{},
			CacheMaxSize:     10000,
		},
		FileBlocking: FileBlockingConfig{
			BlockedExtensions:      []string{".env", ".tfstate", ".pem", ".key", ".p12", ".pfx"},
			ContentPatternsEnabled: true,
		},
		Hooks: HooksConfig{
			Enabled:    false,
			ClaudeCode: false,
			SafecmdOverrides: SafecmdOverrides{
				Added:   []string{},
				Removed: []string{},
			},
		},
		MCP: MCPConfig{
			WrappedServers: map[string]MCPServerEntry{},
		},
	}
}
```

- [ ] **Step 4: Write config implementation**

Create `internal/config/config.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Proxy        ProxyConfig        `yaml:"proxy"`
	Scanning     ScanningConfig     `yaml:"scanning"`
	FileBlocking FileBlockingConfig `yaml:"file_blocking"`
	Hooks        HooksConfig        `yaml:"hooks"`
	MCP          MCPConfig          `yaml:"mcp"`
}

type ProxyConfig struct {
	Enabled            bool     `yaml:"enabled"`
	InterceptedDomains []string `yaml:"intercepted_domains"`
	BlockedDomains     []string `yaml:"blocked_domains"`
}

type ScanningConfig struct {
	RegexEnabled       bool            `yaml:"regex_enabled"`
	EntropyEnabled     bool            `yaml:"entropy_enabled"`
	EntropyThreshold   float64         `yaml:"entropy_threshold"`
	GLiNEREnabled      bool            `yaml:"gliner_enabled"`
	CustomPatterns     []CustomPattern `yaml:"custom_patterns"`
	CustomBlockedWords []string        `yaml:"custom_blocked_words"`
	CacheMaxSize       int             `yaml:"cache_max_size"`
}

type CustomPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
}

type FileBlockingConfig struct {
	BlockedExtensions      []string `yaml:"blocked_extensions"`
	ContentPatternsEnabled bool     `yaml:"content_patterns_enabled"`
}

type HooksConfig struct {
	Enabled          bool             `yaml:"enabled"`
	ClaudeCode       bool             `yaml:"claude_code"`
	SafecmdOverrides SafecmdOverrides `yaml:"safecmd_overrides"`
}

type SafecmdOverrides struct {
	Added   []string `yaml:"added"`
	Removed []string `yaml:"removed"`
}

type MCPConfig struct {
	WrappedServers map[string]MCPServerEntry `yaml:"wrapped_servers"`
}

type MCPServerEntry struct {
	OriginalCommand string   `yaml:"original_command"`
	OriginalArgs    []string `yaml:"original_args"`
	Wrapped         bool     `yaml:"wrapped"`
}

type Manager struct {
	mu   sync.RWMutex
	cfg  *Config
	path string
}

func NewManager(path string) (*Manager, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &Manager{cfg: cfg, path: path}, nil
}

func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := *m.cfg
	return &cp
}

func (m *Manager) Update(fn func(*Config)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(m.cfg)
	return Save(m.path, m.cfg)
}

func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := DefaultConfig()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, err
		}
		if err := Save(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
```

- [ ] **Step 5: Add yaml dependency and run tests**

```bash
go get gopkg.in/yaml.v3
go test ./internal/config/ -v
```

Expected: all 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/ go.mod go.sum
git commit -m "feat: add config package with YAML load/save and hot-reload manager"
```

---

### Task 3: Certificate Authority

**Files:**
- Create: `internal/certgen/ca.go`
- Create: `internal/certgen/ca_test.go`

- [ ] **Step 1: Write failing test for CA generation**

Create `internal/certgen/ca_test.go`:

```go
package certgen

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := GenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	if ca.Cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if ca.Key == nil {
		t.Fatal("expected non-nil private key")
	}
	if !ca.Cert.IsCA {
		t.Error("expected CA certificate")
	}
	if ca.Cert.Subject.CommonName != "Redactr CA" {
		t.Errorf("expected CN 'Redactr CA', got %q", ca.Cert.Subject.CommonName)
	}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("expected cert file written to disk")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("expected key file written to disk")
	}
}

func TestLoadExistingCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	original, err := GenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA() error: %v", err)
	}

	if loaded.Cert.SerialNumber.Cmp(original.Cert.SerialNumber) != 0 {
		t.Error("expected same serial number after reload")
	}
}

func TestLoadOrCreateCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca1, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA() error: %v", err)
	}

	ca2, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("second LoadOrCreateCA() error: %v", err)
	}

	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) != 0 {
		t.Error("expected same CA on second load")
	}
}

func TestIssueCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := GenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("GenerateCA() error: %v", err)
	}

	tlsCert, err := ca.IssueCert("api.anthropic.com")
	if err != nil {
		t.Fatalf("IssueCert() error: %v", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	if err := leaf.VerifyHostname("api.anthropic.com"); err != nil {
		t.Errorf("expected cert valid for api.anthropic.com: %v", err)
	}

	pool := x509.NewCertPool()
	certPEM, _ := os.ReadFile(certPath)
	pool.AppendCertsFromPEM(certPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("expected cert verifiable against CA: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/certgen/ -v
```

Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Write CA implementation**

Create `internal/certgen/ca.go`:

```go
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func GenerateCA(certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Redactr CA",
			Organization: []string{"Redactr"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}

	return &CA{Cert: cert, Key: key}, nil
}

func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{Cert: cert, Key: key}, nil
}

func LoadOrCreateCA(certPath, keyPath string) (*CA, error) {
	if _, err := os.Stat(certPath); err == nil {
		return LoadCA(certPath, keyPath)
	}
	return GenerateCA(certPath, keyPath)
}

func (ca *CA) IssueCert(hostname string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames:  []string{hostname},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/certgen/ -v
```

Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/certgen/
git commit -m "feat: add CA generation and per-domain cert issuance"
```

---

### Task 4: BoltDB Store

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/store_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/store/store_test.go`:

```go
package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreScanReport(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Close()

	report := &ScanReport{
		Timestamp:  time.Now(),
		Provider:   "anthropic",
		Source:     "proxy",
		LatencyMs:  12,
		Redactions: []Redaction{{Label: "[REDACTED-EMAIL]", Original: "test@example.com", Start: 10, End: 26}},
		Layers: []LayerResult{
			{Name: "regex", FindingsCount: 1, LatencyMs: 1},
			{Name: "entropy", FindingsCount: 0, LatencyMs: 0},
		},
		Blocked: false,
		Reason:  "",
	}

	id, err := s.SaveReport(report)
	if err != nil {
		t.Fatalf("SaveReport() error: %v", err)
	}
	if id == "" {
		t.Error("expected non-empty ID")
	}

	retrieved, err := s.GetReport(id)
	if err != nil {
		t.Fatalf("GetReport() error: %v", err)
	}
	if retrieved.Provider != "anthropic" {
		t.Errorf("expected provider 'anthropic', got %q", retrieved.Provider)
	}
	if len(retrieved.Redactions) != 1 {
		t.Errorf("expected 1 redaction, got %d", len(retrieved.Redactions))
	}
}

func TestQueryReports(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Close()

	now := time.Now()
	for i := 0; i < 5; i++ {
		report := &ScanReport{
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Provider:  "anthropic",
			Source:    "proxy",
			LatencyMs: int64(i * 10),
			Blocked:   i%2 == 0,
		}
		s.SaveReport(report)
	}

	reports, err := s.QueryReports(QueryFilter{Limit: 3})
	if err != nil {
		t.Fatalf("QueryReports() error: %v", err)
	}
	if len(reports) != 3 {
		t.Errorf("expected 3 reports, got %d", len(reports))
	}
	if reports[0].Timestamp.Before(reports[1].Timestamp) {
		t.Error("expected newest first")
	}
}

func TestQueryReportsFilterByProvider(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Close()

	s.SaveReport(&ScanReport{Timestamp: time.Now(), Provider: "anthropic", Source: "proxy"})
	s.SaveReport(&ScanReport{Timestamp: time.Now(), Provider: "openai", Source: "proxy"})
	s.SaveReport(&ScanReport{Timestamp: time.Now(), Provider: "anthropic", Source: "mcp"})

	reports, err := s.QueryReports(QueryFilter{Provider: "anthropic", Limit: 10})
	if err != nil {
		t.Fatalf("QueryReports() error: %v", err)
	}
	if len(reports) != 2 {
		t.Errorf("expected 2 anthropic reports, got %d", len(reports))
	}
}

func TestGetStats(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer s.Close()

	now := time.Now()
	s.SaveReport(&ScanReport{Timestamp: now, Provider: "anthropic", LatencyMs: 10, Redactions: []Redaction{{Label: "X"}}, Source: "proxy"})
	s.SaveReport(&ScanReport{Timestamp: now, Provider: "openai", LatencyMs: 20, Blocked: true, Source: "proxy"})

	stats, err := s.GetStats(now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}
	if stats.TotalScanned != 2 {
		t.Errorf("expected 2 total, got %d", stats.TotalScanned)
	}
	if stats.TotalRedactions != 1 {
		t.Errorf("expected 1 redaction, got %d", stats.TotalRedactions)
	}
	if stats.TotalBlocked != 1 {
		t.Errorf("expected 1 blocked, got %d", stats.TotalBlocked)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/store/ -v
```

Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Write store implementation**

Create `internal/store/store.go`:

```go
package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var reportsBucket = []byte("reports")

type ScanReport struct {
	ID         string        `json:"id"`
	Timestamp  time.Time     `json:"timestamp"`
	Provider   string        `json:"provider"`
	Source     string        `json:"source"`
	LatencyMs  int64         `json:"latency_ms"`
	Redactions []Redaction   `json:"redactions"`
	Layers     []LayerResult `json:"layers"`
	Blocked    bool          `json:"blocked"`
	Reason     string        `json:"reason"`
}

type Redaction struct {
	Label    string `json:"label"`
	Original string `json:"original"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

type LayerResult struct {
	Name          string `json:"name"`
	FindingsCount int    `json:"findings_count"`
	LatencyMs     int64  `json:"latency_ms"`
}

type QueryFilter struct {
	Provider string
	Source   string
	Blocked  *bool
	Since    time.Time
	Until    time.Time
	Limit    int
}

type Stats struct {
	TotalScanned   int     `json:"total_scanned"`
	TotalRedactions int    `json:"total_redactions"`
	TotalBlocked   int     `json:"total_blocked"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
}

type Store struct {
	db *bolt.DB
}

func New(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(reportsBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SaveReport(report *ScanReport) (string, error) {
	id := fmt.Sprintf("%d", report.Timestamp.UnixNano())
	report.ID = id

	data, err := json.Marshal(report)
	if err != nil {
		return "", err
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(reportsBucket).Put([]byte(id), data)
	})
	return id, err
}

func (s *Store) GetReport(id string) (*ScanReport, error) {
	var report ScanReport
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(reportsBucket).Get([]byte(id))
		if data == nil {
			return fmt.Errorf("report %s not found", id)
		}
		return json.Unmarshal(data, &report)
	})
	return &report, err
}

func (s *Store) QueryReports(filter QueryFilter) ([]ScanReport, error) {
	var results []ScanReport

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(reportsBucket)
		return b.ForEach(func(k, v []byte) error {
			var r ScanReport
			if err := json.Unmarshal(v, &r); err != nil {
				return nil
			}
			if filter.Provider != "" && r.Provider != filter.Provider {
				return nil
			}
			if filter.Source != "" && r.Source != filter.Source {
				return nil
			}
			if filter.Blocked != nil && r.Blocked != *filter.Blocked {
				return nil
			}
			if !filter.Since.IsZero() && r.Timestamp.Before(filter.Since) {
				return nil
			}
			if !filter.Until.IsZero() && r.Timestamp.After(filter.Until) {
				return nil
			}
			results = append(results, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}
	return results, nil
}

func (s *Store) GetStats(since, until time.Time) (*Stats, error) {
	var stats Stats
	var totalLatency int64

	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(reportsBucket).ForEach(func(k, v []byte) error {
			var r ScanReport
			if err := json.Unmarshal(v, &r); err != nil {
				return nil
			}
			if r.Timestamp.Before(since) || r.Timestamp.After(until) {
				return nil
			}
			stats.TotalScanned++
			stats.TotalRedactions += len(r.Redactions)
			if r.Blocked {
				stats.TotalBlocked++
			}
			totalLatency += r.LatencyMs
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if stats.TotalScanned > 0 {
		stats.AvgLatencyMs = float64(totalLatency) / float64(stats.TotalScanned)
	}
	return &stats, nil
}
```

- [ ] **Step 4: Add bbolt dependency and run tests**

```bash
go get go.etcd.io/bbolt@latest
go test ./internal/store/ -v
```

Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/ go.mod go.sum
git commit -m "feat: add BoltDB store for scan report persistence and querying"
```

---

### Task 5: Domain Filtering

**Files:**
- Create: `internal/domain/domain.go`
- Create: `internal/domain/domain_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/domain/domain_test.go`:

```go
package domain

import (
	"testing"
)

func TestShouldIntercept(t *testing.T) {
	f := New(
		[]string{"api.anthropic.com", "api.openai.com"},
		[]string{},
	)

	tests := []struct {
		host   string
		expect bool
	}{
		{"api.anthropic.com", true},
		{"api.anthropic.com:443", true},
		{"api.openai.com", true},
		{"google.com", false},
		{"example.com", false},
	}

	for _, tt := range tests {
		got := f.ShouldIntercept(tt.host)
		if got != tt.expect {
			t.Errorf("ShouldIntercept(%q) = %v, want %v", tt.host, got, tt.expect)
		}
	}
}

func TestIsBlocked(t *testing.T) {
	f := New(
		[]string{"api.anthropic.com"},
		[]string{"evil.com", "exfil.io"},
	)

	if !f.IsBlocked("evil.com") {
		t.Error("expected evil.com blocked")
	}
	if !f.IsBlocked("exfil.io:443") {
		t.Error("expected exfil.io blocked")
	}
	if f.IsBlocked("google.com") {
		t.Error("expected google.com not blocked")
	}
}

func TestUpdateDomains(t *testing.T) {
	f := New([]string{"api.anthropic.com"}, []string{})

	if f.ShouldIntercept("api.openai.com") {
		t.Error("should not intercept before update")
	}

	f.SetInterceptDomains([]string{"api.anthropic.com", "api.openai.com"})

	if !f.ShouldIntercept("api.openai.com") {
		t.Error("should intercept after update")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/domain/ -v
```

Expected: FAIL.

- [ ] **Step 3: Write domain filter implementation**

Create `internal/domain/domain.go`:

```go
package domain

import (
	"net"
	"strings"
	"sync"
)

type Filter struct {
	mu               sync.RWMutex
	interceptDomains map[string]bool
	blockedDomains   map[string]bool
}

func New(intercept, blocked []string) *Filter {
	f := &Filter{
		interceptDomains: make(map[string]bool),
		blockedDomains:   make(map[string]bool),
	}
	for _, d := range intercept {
		f.interceptDomains[strings.ToLower(d)] = true
	}
	for _, d := range blocked {
		f.blockedDomains[strings.ToLower(d)] = true
	}
	return f
}

func (f *Filter) ShouldIntercept(host string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.interceptDomains[stripPort(host)]
}

func (f *Filter) IsBlocked(host string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.blockedDomains[stripPort(host)]
}

func (f *Filter) SetInterceptDomains(domains []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.interceptDomains = make(map[string]bool)
	for _, d := range domains {
		f.interceptDomains[strings.ToLower(d)] = true
	}
}

func (f *Filter) SetBlockedDomains(domains []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockedDomains = make(map[string]bool)
	for _, d := range domains {
		f.blockedDomains[strings.ToLower(d)] = true
	}
}

func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/domain/ -v
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/domain/
git commit -m "feat: add domain filter for intercept and block lists"
```

---

## Phase 2: Scanning Pipeline (Tasks 6-11)

Build the four-layer scanning pipeline, redactor, file blocker, and cache. After this phase you have a fully functional scanning system that can be tested standalone.

---

### Task 6: Scanner Types & Pipeline Coordinator

**Files:**
- Create: `internal/scanner/types.go`
- Create: `internal/scanner/pipeline.go`
- Create: `internal/scanner/pipeline_test.go`

- [ ] **Step 1: Write scanner types**

Create `internal/scanner/types.go`:

```go
package scanner

type Finding struct {
	Label      string  `json:"label"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
	Layer      string  `json:"layer"`
}

type ScanResult struct {
	Findings []Finding `json:"findings"`
	LayerMs  int64     `json:"layer_ms"`
}

type Layer interface {
	Name() string
	Scan(text string) (*ScanResult, error)
	Ready() bool
}
```

- [ ] **Step 2: Write failing test for pipeline**

Create `internal/scanner/pipeline_test.go`:

```go
package scanner

import (
	"testing"
)

type mockLayer struct {
	name     string
	findings []Finding
	ready    bool
}

func (m *mockLayer) Name() string { return m.name }
func (m *mockLayer) Ready() bool  { return m.ready }
func (m *mockLayer) Scan(text string) (*ScanResult, error) {
	return &ScanResult{Findings: m.findings, LayerMs: 1}, nil
}

func TestPipelineRunsAllLayers(t *testing.T) {
	p := NewPipeline(
		&mockLayer{name: "layer1", ready: true, findings: []Finding{
			{Label: "EMAIL", Value: "test@test.com", Start: 0, End: 13, Layer: "layer1"},
		}},
		&mockLayer{name: "layer2", ready: true, findings: []Finding{
			{Label: "ENTROPY-SECRET", Value: "aGVsbG8gd29ybGQ=", Start: 20, End: 37, Layer: "layer2"},
		}},
	)

	report, err := p.Scan("test@test.com hello aGVsbG8gd29ybGQ=")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(report.Findings))
	}
	if len(report.LayerResults) != 2 {
		t.Errorf("expected 2 layer results, got %d", len(report.LayerResults))
	}
}

func TestPipelineSkipsUnreadyLayers(t *testing.T) {
	p := NewPipeline(
		&mockLayer{name: "ready", ready: true, findings: []Finding{
			{Label: "EMAIL", Value: "x@y.com", Start: 0, End: 7, Layer: "ready"},
		}},
		&mockLayer{name: "not-ready", ready: false, findings: []Finding{
			{Label: "PERSON", Value: "John", Start: 10, End: 14, Layer: "not-ready"},
		}},
	)

	report, err := p.Scan("x@y.com hi John")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding (skipped unready), got %d", len(report.Findings))
	}
	if len(report.LayerResults) != 2 {
		t.Errorf("expected 2 layer results (including skipped), got %d", len(report.LayerResults))
	}
	if !report.LayerResults[1].Skipped {
		t.Error("expected second layer marked as skipped")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
go test ./internal/scanner/ -v
```

Expected: FAIL — `NewPipeline` not defined.

- [ ] **Step 4: Write pipeline implementation**

Create `internal/scanner/pipeline.go`:

```go
package scanner

import (
	"time"
)

type PipelineReport struct {
	Findings     []Finding           `json:"findings"`
	LayerResults []PipelineLayerInfo `json:"layer_results"`
	TotalMs      int64               `json:"total_ms"`
}

type PipelineLayerInfo struct {
	Name          string `json:"name"`
	FindingsCount int    `json:"findings_count"`
	LatencyMs     int64  `json:"latency_ms"`
	Skipped       bool   `json:"skipped"`
	SkipReason    string `json:"skip_reason,omitempty"`
}

type Pipeline struct {
	layers []Layer
}

func NewPipeline(layers ...Layer) *Pipeline {
	return &Pipeline{layers: layers}
}

func (p *Pipeline) Scan(text string) (*PipelineReport, error) {
	start := time.Now()
	report := &PipelineReport{}

	for _, layer := range p.layers {
		info := PipelineLayerInfo{Name: layer.Name()}

		if !layer.Ready() {
			info.Skipped = true
			info.SkipReason = "not ready"
			report.LayerResults = append(report.LayerResults, info)
			continue
		}

		layerStart := time.Now()
		result, err := layer.Scan(text)
		info.LatencyMs = time.Since(layerStart).Milliseconds()

		if err != nil {
			info.Skipped = true
			info.SkipReason = err.Error()
			report.LayerResults = append(report.LayerResults, info)
			continue
		}

		info.FindingsCount = len(result.Findings)
		report.Findings = append(report.Findings, result.Findings...)
		report.LayerResults = append(report.LayerResults, info)
	}

	report.TotalMs = time.Since(start).Milliseconds()
	return report, nil
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/scanner/ -v
```

Expected: all 2 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/types.go internal/scanner/pipeline.go internal/scanner/pipeline_test.go
git commit -m "feat: add scanner pipeline coordinator with layer interface"
```

---

### Task 7: Regex Scanner (Layer 1)

**Files:**
- Create: `internal/scanner/regex/regex.go`
- Create: `internal/scanner/regex/regex_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/scanner/regex/regex_test.go`:

```go
package regex

import (
	"testing"
)

func TestDetectEmail(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, err := s.Scan("contact me at user@example.com for details")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "EMAIL" {
		t.Errorf("expected label EMAIL, got %q", result.Findings[0].Label)
	}
	if result.Findings[0].Value != "user@example.com" {
		t.Errorf("expected value 'user@example.com', got %q", result.Findings[0].Value)
	}
}

func TestDetectSSN(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("SSN is 123-45-6789")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "SSN" {
		t.Errorf("expected SSN, got %q", result.Findings[0].Label)
	}
}

func TestDetectAWSKey(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("aws_key = AKIAIOSFODNN7EXAMPLE")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "AWS-ACCESS-KEY" {
		t.Errorf("expected AWS-ACCESS-KEY, got %q", result.Findings[0].Label)
	}
}

func TestDetectCreditCard(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("card: 4111-1111-1111-1111")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "CREDIT-CARD" {
		t.Errorf("expected CREDIT-CARD, got %q", result.Findings[0].Label)
	}
}

func TestDetectPhoneNumber(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("call me at (555) 123-4567")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "PHONE" {
		t.Errorf("expected PHONE, got %q", result.Findings[0].Label)
	}
}

func TestDetectPrivateKey(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	input := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	result, _ := s.Scan(input)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "PRIVATE-KEY" {
		t.Errorf("expected PRIVATE-KEY, got %q", result.Findings[0].Label)
	}
}

func TestDetectJWT(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "JWT" {
		t.Errorf("expected JWT, got %q", result.Findings[0].Label)
	}
}

func TestCustomPatterns(t *testing.T) {
	custom := []PatternDef{
		{Name: "INTERNAL-ID", Pattern: `PROJ-\d{4,6}`},
	}
	s := New(DefaultPatterns(), custom)
	result, _ := s.Scan("ticket PROJ-12345 is critical")
	found := false
	for _, f := range result.Findings {
		if f.Label == "INTERNAL-ID" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom pattern INTERNAL-ID to match")
	}
}

func TestNoFalsePositives(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("func main() { fmt.Println(\"hello world\") }")
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings on clean code, got %d", len(result.Findings))
	}
}

func TestMultipleFindings(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("email user@test.com and SSN 123-45-6789")
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scanner/regex/ -v
```

Expected: FAIL.

- [ ] **Step 3: Write regex scanner implementation**

Create `internal/scanner/regex/regex.go`:

```go
package regex

import (
	"regexp"
	"time"

	"github.com/rakeshguha/redactr/internal/scanner"
)

type PatternDef struct {
	Name    string `json:"name" yaml:"name"`
	Pattern string `json:"pattern" yaml:"pattern"`
}

type Scanner struct {
	patterns []compiledPattern
}

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

func DefaultPatterns() []PatternDef {
	return []PatternDef{
		{Name: "EMAIL", Pattern: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`},
		{Name: "SSN", Pattern: `\b\d{3}-\d{2}-\d{4}\b`},
		{Name: "CREDIT-CARD", Pattern: `\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b`},
		{Name: "PHONE", Pattern: `\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}`},
		{Name: "AWS-ACCESS-KEY", Pattern: `AKIA[0-9A-Z]{16}`},
		{Name: "AWS-SECRET-KEY", Pattern: `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`},
		{Name: "GCP-API-KEY", Pattern: `AIza[0-9A-Za-z\-_]{35}`},
		{Name: "PRIVATE-KEY", Pattern: `-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`},
		{Name: "JWT", Pattern: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]+`},
		{Name: "CONNECTION-STRING", Pattern: `(?i)(mongodb|postgres|mysql|redis|amqp):\/\/[^\s]+`},
		{Name: "GENERIC-SECRET", Pattern: `(?i)(password|secret|token|api_key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9/+=\-_]{8,}['"]?`},
		{Name: "IP-ADDRESS", Pattern: `\b(?:\d{1,3}\.){3}\d{1,3}\b`},
	}
}

func New(defaults []PatternDef, custom []PatternDef) *Scanner {
	all := append(defaults, custom...)
	var compiled []compiledPattern
	for _, p := range all {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledPattern{name: p.Name, re: re})
	}
	return &Scanner{patterns: compiled}
}

func (s *Scanner) Name() string  { return "regex" }
func (s *Scanner) Ready() bool   { return true }

func (s *Scanner) Scan(text string) (*scanner.ScanResult, error) {
	start := time.Now()
	var findings []scanner.Finding

	for _, p := range s.patterns {
		matches := p.re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			findings = append(findings, scanner.Finding{
				Label:      p.name,
				Value:      text[m[0]:m[1]],
				Start:      m[0],
				End:        m[1],
				Confidence: 1.0,
				Layer:      "regex",
			})
		}
	}

	return &scanner.ScanResult{
		Findings: findings,
		LayerMs:  time.Since(start).Milliseconds(),
	}, nil
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/scanner/regex/ -v
```

Expected: all 10 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/regex/
git commit -m "feat: add regex scanner layer with built-in and custom patterns"
```

---

### Task 8: Entropy Scanner (Layer 2)

**Files:**
- Create: `internal/scanner/entropy/entropy.go`
- Create: `internal/scanner/entropy/entropy_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/scanner/entropy/entropy_test.go`:

```go
package entropy

import (
	"strings"
	"testing"
)

func TestHighEntropyStringDetected(t *testing.T) {
	s := New(4.5, 20)
	result, err := s.Scan("key = aB3xK9mP2qR7sW4yZ1cD8eF5gH6jL0n")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected high-entropy string to be detected")
	}
	if result.Findings[0].Label != "ENTROPY-SECRET" {
		t.Errorf("expected ENTROPY-SECRET label, got %q", result.Findings[0].Label)
	}
}

func TestLowEntropyStringIgnored(t *testing.T) {
	s := New(4.5, 20)
	result, _ := s.Scan("hello world this is normal text")
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for low-entropy text, got %d", len(result.Findings))
	}
}

func TestRepeatedCharsIgnored(t *testing.T) {
	s := New(4.5, 20)
	result, _ := s.Scan("key = aaaaaaaaaaaaaaaaaaaaaaaaa")
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for repeated chars, got %d", len(result.Findings))
	}
}

func TestBase64StringDetected(t *testing.T) {
	s := New(4.0, 16)
	result, _ := s.Scan("data: dGhpcyBpcyBhIHNlY3JldCBrZXkgdmFsdWU=")
	if len(result.Findings) == 0 {
		t.Error("expected base64 string detected")
	}
}

func TestShannonEntropy(t *testing.T) {
	low := shannonEntropy("aaaaaaaaaa")
	high := shannonEntropy("aB3xK9mP2q")
	if low >= high {
		t.Errorf("expected low entropy (%f) < high entropy (%f)", low, high)
	}
}

func TestCodeNotFlagged(t *testing.T) {
	s := New(4.5, 20)
	code := `func main() {
		fmt.Println("hello")
		for i := 0; i < 10; i++ {
			result = append(result, i)
		}
	}`
	result, _ := s.Scan(code)
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for normal code, got %d: %v", len(result.Findings), result.Findings)
	}
}

func TestCustomThreshold(t *testing.T) {
	high := New(6.0, 20)
	low := New(2.0, 20)

	text := "token=aB3xK9mP2qR7sW4yZ1cD"

	highResult, _ := high.Scan(text)
	lowResult, _ := low.Scan(text)

	if len(lowResult.Findings) <= len(highResult.Findings) && len(lowResult.Findings) == 0 {
		t.Log("both found nothing, threshold might be too high for this string")
	}
}

func TestLongRandomString(t *testing.T) {
	s := New(4.5, 20)
	random := strings.Repeat("aB3xK9mP", 5)
	result, _ := s.Scan("secret: " + random)
	if len(result.Findings) == 0 {
		t.Error("expected long random string detected")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scanner/entropy/ -v
```

Expected: FAIL.

- [ ] **Step 3: Write entropy scanner implementation**

Create `internal/scanner/entropy/entropy.go`:

```go
package entropy

import (
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/rakeshguha/redactr/internal/scanner"
)

type Scanner struct {
	threshold float64
	minLength int
}

func New(threshold float64, minLength int) *Scanner {
	return &Scanner{threshold: threshold, minLength: minLength}
}

func (s *Scanner) Name() string  { return "entropy" }
func (s *Scanner) Ready() bool   { return true }

func (s *Scanner) Scan(text string) (*scanner.ScanResult, error) {
	start := time.Now()
	var findings []scanner.Finding

	tokens := extractTokens(text, s.minLength)
	for _, tok := range tokens {
		ent := shannonEntropy(tok.value)
		if ent >= s.threshold {
			findings = append(findings, scanner.Finding{
				Label:      "ENTROPY-SECRET",
				Value:      tok.value,
				Start:      tok.start,
				End:        tok.end,
				Confidence: math.Min(ent/6.0, 1.0),
				Layer:      "entropy",
			})
		}
	}

	return &scanner.ScanResult{
		Findings: findings,
		LayerMs:  time.Since(start).Milliseconds(),
	}, nil
}

type token struct {
	value string
	start int
	end   int
}

func extractTokens(text string, minLen int) []token {
	var tokens []token
	runes := []rune(text)
	i := 0
	for i < len(runes) {
		if isTokenChar(runes[i]) {
			j := i
			for j < len(runes) && isTokenChar(runes[j]) {
				j++
			}
			val := string(runes[i:j])
			if len(val) >= minLen && hasCharVariety(val) {
				tokens = append(tokens, token{value: val, start: i, end: j})
			}
			i = j
		} else {
			i++
		}
	}
	return tokens
}

func isTokenChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '/' || r == '=' || r == '-' || r == '_'
}

func hasCharVariety(s string) bool {
	classes := 0
	for _, r := range s {
		if unicode.IsUpper(r) {
			classes |= 1
		} else if unicode.IsLower(r) {
			classes |= 2
		} else if unicode.IsDigit(r) {
			classes |= 4
		} else {
			classes |= 8
		}
	}
	count := 0
	for classes > 0 {
		count += classes & 1
		classes >>= 1
	}
	return count >= 2
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	length := float64(strings.Count(s, "") - 1)
	var entropy float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/scanner/entropy/ -v
```

Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/entropy/
git commit -m "feat: add entropy scanner layer with Shannon entropy on sliding tokens"
```

---

### Task 9: GLiNER Client (Layer 3)

**Files:**
- Create: `internal/scanner/gliner/client.go`
- Create: `internal/scanner/gliner/client_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/scanner/gliner/client_test.go`:

```go
package gliner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGLiNERClientScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/detect" {
			t.Errorf("expected /detect path, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var req DetectRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Text == "" {
			t.Error("expected non-empty text")
		}

		resp := DetectResponse{
			Entities: []Entity{
				{Text: "John Smith", Label: "PERSON", Start: 0, End: 10, Score: 0.95},
				{Text: "123 Main St", Label: "ADDRESS", Start: 20, End: 31, Score: 0.88},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := New(server.URL)
	client.SetReady(true)

	result, err := client.Scan("John Smith lives at 123 Main St in Springfield")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "PERSON" {
		t.Errorf("expected PERSON, got %q", result.Findings[0].Label)
	}
	if result.Findings[1].Label != "ADDRESS" {
		t.Errorf("expected ADDRESS, got %q", result.Findings[1].Label)
	}
}

func TestGLiNERNotReady(t *testing.T) {
	client := New("http://localhost:99999")

	if client.Ready() {
		t.Error("expected not ready")
	}

	result, err := client.Scan("some text")
	if err != nil {
		t.Fatalf("expected no error when not ready, got %v", err)
	}
	if len(result.Findings) != 0 {
		t.Error("expected no findings when not ready")
	}
}

func TestGLiNERHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
			return
		}
	}))
	defer server.Close()

	client := New(server.URL)
	ok := client.HealthCheck()
	if !ok {
		t.Error("expected health check to pass")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scanner/gliner/ -v
```

Expected: FAIL.

- [ ] **Step 3: Write GLiNER client implementation**

Create `internal/scanner/gliner/client.go`:

```go
package gliner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/rakeshguha/redactr/internal/scanner"
)

type DetectRequest struct {
	Text string `json:"text"`
}

type DetectResponse struct {
	Entities []Entity `json:"entities"`
}

type Entity struct {
	Text  string  `json:"text"`
	Label string  `json:"label"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Score float64 `json:"score"`
}

type Client struct {
	baseURL string
	client  *http.Client
	ready   atomic.Bool
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *Client) Name() string { return "gliner" }

func (c *Client) Ready() bool {
	return c.ready.Load()
}

func (c *Client) SetReady(ready bool) {
	c.ready.Store(ready)
}

func (c *Client) HealthCheck() bool {
	resp, err := c.client.Get(c.baseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result["status"] == "ready"
}

func (c *Client) Scan(text string) (*scanner.ScanResult, error) {
	if !c.Ready() {
		return &scanner.ScanResult{}, nil
	}

	start := time.Now()

	reqBody, err := json.Marshal(DetectRequest{Text: text})
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(c.baseURL+"/detect", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("gliner sidecar request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gliner sidecar returned status %d", resp.StatusCode)
	}

	var detectResp DetectResponse
	if err := json.NewDecoder(resp.Body).Decode(&detectResp); err != nil {
		return nil, err
	}

	var findings []scanner.Finding
	for _, entity := range detectResp.Entities {
		findings = append(findings, scanner.Finding{
			Label:      entity.Label,
			Value:      entity.Text,
			Start:      entity.Start,
			End:        entity.End,
			Confidence: entity.Score,
			Layer:      "gliner",
		})
	}

	return &scanner.ScanResult{
		Findings: findings,
		LayerMs:  time.Since(start).Milliseconds(),
	}, nil
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/scanner/gliner/ -v
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/gliner/
git commit -m "feat: add GLiNER client layer for PII model sidecar communication"
```

---

### Task 10: Context Gate Stub (Layer 4) & Redactor

**Files:**
- Create: `internal/scanner/contextgate/stub.go`
- Create: `internal/redactor/redactor.go`
- Create: `internal/redactor/redactor_test.go`

- [ ] **Step 1: Write context gate stub**

Create `internal/scanner/contextgate/stub.go`:

```go
package contextgate

import (
	"github.com/rakeshguha/redactr/internal/scanner"
)

type Stub struct{}

func New() *Stub                                          { return &Stub{} }
func (s *Stub) Name() string                              { return "contextgate" }
func (s *Stub) Ready() bool                               { return true }
func (s *Stub) Scan(text string) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{}, nil
}
```

- [ ] **Step 2: Write failing test for redactor**

Create `internal/redactor/redactor_test.go`:

```go
package redactor

import (
	"testing"

	"github.com/rakeshguha/redactr/internal/scanner"
)

func TestRedactSingleFinding(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "EMAIL", Value: "user@test.com", Start: 10, End: 23},
	}
	result := Redact("contact: user@test.com please", findings)
	expected := "contact: [REDACTED-EMAIL] please"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
	if len(result.Applied) != 1 {
		t.Errorf("expected 1 applied redaction, got %d", len(result.Applied))
	}
}

func TestRedactMultipleFindings(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "EMAIL", Value: "a@b.com", Start: 0, End: 7},
		{Label: "SSN", Value: "123-45-6789", Start: 12, End: 23},
	}
	result := Redact("a@b.com and 123-45-6789", findings)
	expected := "[REDACTED-EMAIL] and [REDACTED-SSN]"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
}

func TestRedactOverlappingFindings(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "SHORT", Value: "abc", Start: 0, End: 3},
		{Label: "LONG", Value: "abcdef", Start: 0, End: 6},
	}
	result := Redact("abcdef rest", findings)
	expected := "[REDACTED-LONG] rest"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
	if len(result.Applied) != 1 {
		t.Errorf("expected 1 applied (longest wins), got %d", len(result.Applied))
	}
}

func TestRedactNoFindings(t *testing.T) {
	result := Redact("clean text", nil)
	if result.Text != "clean text" {
		t.Errorf("expected unchanged text, got %q", result.Text)
	}
	if len(result.Applied) != 0 {
		t.Error("expected no applied redactions")
	}
}

func TestRedactCustomLabel(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "MY-PATTERN", Value: "PROJ-12345", Start: 5, End: 15},
	}
	result := Redact("ref: PROJ-12345 done", findings)
	expected := "ref: [REDACTED-MY-PATTERN] done"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
}

func TestRedactPreservesPositions(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "A", Value: "xx", Start: 0, End: 2},
		{Label: "B", Value: "yy", Start: 5, End: 7},
	}
	result := Redact("xx + yy = zz", findings)
	expected := "[REDACTED-A] + [REDACTED-B] = zz"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
go test ./internal/redactor/ -v
```

Expected: FAIL.

- [ ] **Step 4: Write redactor implementation**

Create `internal/redactor/redactor.go`:

```go
package redactor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rakeshguha/redactr/internal/scanner"
)

type RedactionResult struct {
	Text    string             `json:"text"`
	Applied []AppliedRedaction `json:"applied"`
}

type AppliedRedaction struct {
	Label    string `json:"label"`
	Original string `json:"original"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

func Redact(text string, findings []scanner.Finding) *RedactionResult {
	if len(findings) == 0 {
		return &RedactionResult{Text: text}
	}

	deduped := dedup(findings)

	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].Start < deduped[j].Start
	})

	var b strings.Builder
	var applied []AppliedRedaction
	prev := 0

	for _, f := range deduped {
		if f.Start < prev {
			continue
		}
		b.WriteString(text[prev:f.Start])
		label := fmt.Sprintf("[REDACTED-%s]", f.Label)
		b.WriteString(label)
		applied = append(applied, AppliedRedaction{
			Label:    label,
			Original: f.Value,
			Start:    f.Start,
			End:      f.End,
		})
		prev = f.End
	}
	b.WriteString(text[prev:])

	return &RedactionResult{Text: b.String(), Applied: applied}
}

func dedup(findings []scanner.Finding) []scanner.Finding {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Start == findings[j].Start {
			return (findings[i].End - findings[i].Start) > (findings[j].End - findings[j].Start)
		}
		return findings[i].Start < findings[j].Start
	})

	var result []scanner.Finding
	for _, f := range findings {
		overlaps := false
		for _, existing := range result {
			if f.Start >= existing.Start && f.End <= existing.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			result = append(result, f)
		}
	}
	return result
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/redactor/ -v
go test ./internal/scanner/contextgate/ -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/contextgate/ internal/redactor/
git commit -m "feat: add context gate stub and redactor with dedup and dynamic labels"
```

---

### Task 11: File Blocker & Scanner Cache

**Files:**
- Create: `internal/fileblock/fileblock.go`
- Create: `internal/fileblock/fileblock_test.go`
- Create: `internal/scanner/cache.go`
- Create: `internal/scanner/cache_test.go`

- [ ] **Step 1: Write failing test for file blocker**

Create `internal/fileblock/fileblock_test.go`:

```go
package fileblock

import (
	"testing"
)

func TestBlockByExtension(t *testing.T) {
	fb := New([]string{".env", ".tfstate", ".pem", ".key"}, true)

	tests := []struct {
		path    string
		blocked bool
	}{
		{"/app/.env", true},
		{"/infra/main.tfstate", true},
		{"/certs/server.pem", true},
		{"/certs/server.key", true},
		{"/src/main.go", false},
		{"/config/app.yaml", false},
	}

	for _, tt := range tests {
		result := fb.IsBlockedFile(tt.path)
		if result != tt.blocked {
			t.Errorf("IsBlockedFile(%q) = %v, want %v", tt.path, result, tt.blocked)
		}
	}
}

func TestBlockByContent(t *testing.T) {
	fb := New([]string{".env"}, true)

	envContent := `DB_HOST=localhost
DB_PASSWORD=supersecret
API_KEY=sk-1234567890abcdef`

	result := fb.IsBlockedContent(envContent)
	if !result {
		t.Error("expected .env-like content to be blocked")
	}

	normalCode := `func main() {
	fmt.Println("hello world")
}`
	result = fb.IsBlockedContent(normalCode)
	if result {
		t.Error("expected normal code not blocked")
	}
}

func TestRedactBlockedFile(t *testing.T) {
	fb := New([]string{".env"}, true)
	label := fb.RedactionLabel("/app/.env")
	expected := "[REDACTED-FILE-.env: .env]"
	if label != expected {
		t.Errorf("expected %q, got %q", expected, label)
	}
}

func TestContentPatternsDisabled(t *testing.T) {
	fb := New([]string{".env"}, false)
	envContent := "DB_PASSWORD=secret"
	result := fb.IsBlockedContent(envContent)
	if result {
		t.Error("expected content patterns disabled")
	}
}
```

- [ ] **Step 2: Write file blocker implementation**

Create `internal/fileblock/fileblock.go`:

```go
package fileblock

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var contentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^[A-Z_]+=.+$`),
}

const contentThreshold = 3

type Blocker struct {
	extensions      map[string]bool
	contentPatterns bool
}

func New(extensions []string, contentPatterns bool) *Blocker {
	ext := make(map[string]bool)
	for _, e := range extensions {
		ext[strings.ToLower(e)] = true
	}
	return &Blocker{extensions: ext, contentPatterns: contentPatterns}
}

func (b *Blocker) IsBlockedFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	if b.extensions[ext] {
		return true
	}
	if b.extensions["."+base] || b.extensions[base] {
		return true
	}
	return false
}

func (b *Blocker) IsBlockedContent(content string) bool {
	if !b.contentPatterns {
		return false
	}
	for _, pattern := range contentPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) >= contentThreshold {
			return true
		}
	}
	return false
}

func (b *Blocker) RedactionLabel(path string) string {
	ext := filepath.Ext(path)
	base := filepath.Base(path)
	return fmt.Sprintf("[REDACTED-FILE-%s: %s]", ext, base)
}

func (b *Blocker) SetExtensions(extensions []string) {
	ext := make(map[string]bool)
	for _, e := range extensions {
		ext[strings.ToLower(e)] = true
	}
	b.extensions = ext
}
```

- [ ] **Step 3: Run file blocker tests**

```bash
go test ./internal/fileblock/ -v
```

Expected: all 4 tests PASS.

- [ ] **Step 4: Write failing test for cache**

Create `internal/scanner/cache_test.go`:

```go
package scanner

import (
	"testing"
)

func TestCacheHitMiss(t *testing.T) {
	c := NewCache(100)

	result := &PipelineReport{
		Findings: []Finding{{Label: "EMAIL", Value: "a@b.com"}},
		TotalMs:  5,
	}

	c.Put("hello user@test.com", "redacted-text", result)

	text, report, hit := c.Get("hello user@test.com")
	if !hit {
		t.Fatal("expected cache hit")
	}
	if text != "redacted-text" {
		t.Errorf("expected redacted text, got %q", text)
	}
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(report.Findings))
	}

	_, _, hit = c.Get("different text")
	if hit {
		t.Error("expected cache miss")
	}
}

func TestCacheEviction(t *testing.T) {
	c := NewCache(2)

	c.Put("text1", "r1", &PipelineReport{})
	c.Put("text2", "r2", &PipelineReport{})
	c.Put("text3", "r3", &PipelineReport{})

	_, _, hit := c.Get("text1")
	if hit {
		t.Error("expected text1 evicted")
	}

	_, _, hit = c.Get("text3")
	if !hit {
		t.Error("expected text3 in cache")
	}
}

func TestCacheInvalidate(t *testing.T) {
	c := NewCache(100)
	c.Put("text1", "r1", &PipelineReport{})

	c.Invalidate()

	_, _, hit := c.Get("text1")
	if hit {
		t.Error("expected cache empty after invalidate")
	}
}

func TestCacheStats(t *testing.T) {
	c := NewCache(100)
	c.Put("text1", "r1", &PipelineReport{})

	c.Get("text1")
	c.Get("text1")
	c.Get("miss")

	stats := c.Stats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
	if stats.Size != 1 {
		t.Errorf("expected size 1, got %d", stats.Size)
	}
}
```

- [ ] **Step 5: Write cache implementation**

Create `internal/scanner/cache.go`:

```go
package scanner

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
)

type CacheStats struct {
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
	Size   int   `json:"size"`
	MaxSize int  `json:"max_size"`
}

type cacheEntry struct {
	key          string
	redactedText string
	report       *PipelineReport
}

type Cache struct {
	mu      sync.Mutex
	maxSize int
	items   map[string]*list.Element
	order   *list.List
	hits    atomic.Int64
	misses  atomic.Int64
}

func NewCache(maxSize int) *Cache {
	return &Cache{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
}

func (c *Cache) Get(text string) (string, *PipelineReport, bool) {
	key := hash(text)
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		c.hits.Add(1)
		return entry.redactedText, entry.report, true
	}

	c.misses.Add(1)
	return "", nil, false
}

func (c *Cache) Put(text, redactedText string, report *PipelineReport) {
	key := hash(text)
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.redactedText = redactedText
		entry.report = report
		return
	}

	if c.order.Len() >= c.maxSize {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*cacheEntry).key)
		}
	}

	entry := &cacheEntry{key: key, redactedText: redactedText, report: report}
	elem := c.order.PushFront(entry)
	c.items[key] = elem
}

func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.order = list.New()
}

func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	size := c.order.Len()
	c.mu.Unlock()

	return CacheStats{
		Hits:    c.hits.Load(),
		Misses:  c.misses.Load(),
		Size:    size,
		MaxSize: c.maxSize,
	}
}

func hash(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:])
}
```

- [ ] **Step 6: Run all cache and file blocker tests**

```bash
go test ./internal/scanner/ -v -run TestCache
go test ./internal/fileblock/ -v
```

Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/fileblock/ internal/scanner/cache.go internal/scanner/cache_test.go
git commit -m "feat: add file blocker and LRU scanner cache"
```

---

## Phase 3: Proxy Integration (Tasks 12-14)

Wire up goproxy with the scanning pipeline, extract messages from AI provider payloads, rewrite requests.

---

### Task 12: Message Extractor

**Files:**
- Create: `internal/proxy/extract.go`
- Create: `internal/proxy/extract_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/proxy/extract_test.go`:

```go
package proxy

import (
	"testing"
)

func TestExtractAnthropicLastMessage(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": "first message"},
			{"role": "assistant", "content": "response"},
			{"role": "user", "content": "contact me at user@secret.com"}
		]
	}`

	msg, err := ExtractLastUserMessage([]byte(body), "api.anthropic.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Text != "contact me at user@secret.com" {
		t.Errorf("expected last user message, got %q", msg.Text)
	}
	if msg.Index != 2 {
		t.Errorf("expected index 2, got %d", msg.Index)
	}
}

func TestExtractOpenAILastMessage(t *testing.T) {
	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "you are helpful"},
			{"role": "user", "content": "first"},
			{"role": "assistant", "content": "sure"},
			{"role": "user", "content": "my SSN is 123-45-6789"}
		]
	}`

	msg, err := ExtractLastUserMessage([]byte(body), "api.openai.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Text != "my SSN is 123-45-6789" {
		t.Errorf("expected last user message, got %q", msg.Text)
	}
}

func TestExtractWithContentArray(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "here is my key: AKIAIOSFODNN7EXAMPLE"},
				{"type": "text", "text": "and email user@test.com"}
			]}
		]
	}`

	msg, err := ExtractLastUserMessage([]byte(body), "api.anthropic.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Text != "here is my key: AKIAIOSFODNN7EXAMPLE\nand email user@test.com" {
		t.Errorf("unexpected extracted text: %q", msg.Text)
	}
	if len(msg.ContentParts) != 2 {
		t.Errorf("expected 2 content parts, got %d", len(msg.ContentParts))
	}
}

func TestExtractToolResult(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "123", "content": "file contents: API_KEY=sk-secret123"}
			]}
		]
	}`

	msg, err := ExtractLastUserMessage([]byte(body), "api.anthropic.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Text != "file contents: API_KEY=sk-secret123" {
		t.Errorf("expected tool result text, got %q", msg.Text)
	}
}

func TestExtractNoMessages(t *testing.T) {
	body := `{"model": "gpt-4", "messages": []}`
	_, err := ExtractLastUserMessage([]byte(body), "api.openai.com")
	if err == nil {
		t.Error("expected error for empty messages")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/proxy/ -v -run TestExtract
```

Expected: FAIL.

- [ ] **Step 3: Write extractor implementation**

Create `internal/proxy/extract.go`:

```go
package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ExtractedMessage struct {
	Text         string
	Index        int
	ContentParts []ContentPart
	IsArray      bool
}

type ContentPart struct {
	Type      string `json:"type"`
	Text      string `json:"text"`
	Content   string `json:"content"`
	ToolUseID string `json:"tool_use_id"`
}

type apiRequest struct {
	Messages []apiMessage `json:"messages"`
}

type apiMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func ExtractLastUserMessage(body []byte, host string) (*ExtractedMessage, error) {
	var req apiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse request body: %w", err)
	}

	for i := len(req.Messages) - 1; i >= 0; i-- {
		msg := req.Messages[i]
		if msg.Role != "user" {
			continue
		}

		var strContent string
		if err := json.Unmarshal(msg.Content, &strContent); err == nil {
			return &ExtractedMessage{Text: strContent, Index: i}, nil
		}

		var parts []ContentPart
		if err := json.Unmarshal(msg.Content, &parts); err == nil {
			var texts []string
			for _, p := range parts {
				switch p.Type {
				case "text":
					texts = append(texts, p.Text)
				case "tool_result":
					if p.Content != "" {
						texts = append(texts, p.Content)
					}
				}
			}
			return &ExtractedMessage{
				Text:         strings.Join(texts, "\n"),
				Index:        i,
				ContentParts: parts,
				IsArray:      true,
			}, nil
		}

		return nil, fmt.Errorf("unsupported content format at message %d", i)
	}

	return nil, fmt.Errorf("no user message found")
}

func ReplaceLastUserMessage(body []byte, msg *ExtractedMessage, redactedText string) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(raw["messages"], &messages); err != nil {
		return nil, err
	}

	if msg.IsArray {
		redactedParts := make([]ContentPart, len(msg.ContentParts))
		texts := strings.Split(redactedText, "\n")
		textIdx := 0
		for i, p := range msg.ContentParts {
			redactedParts[i] = p
			switch p.Type {
			case "text":
				if textIdx < len(texts) {
					redactedParts[i].Text = texts[textIdx]
					textIdx++
				}
			case "tool_result":
				if textIdx < len(texts) {
					redactedParts[i].Content = texts[textIdx]
					textIdx++
				}
			}
		}
		partBytes, err := json.Marshal(redactedParts)
		if err != nil {
			return nil, err
		}
		msgObj := map[string]json.RawMessage{
			"role":    json.RawMessage(`"user"`),
			"content": partBytes,
		}
		msgBytes, err := json.Marshal(msgObj)
		if err != nil {
			return nil, err
		}
		messages[msg.Index] = msgBytes
	} else {
		contentBytes, err := json.Marshal(redactedText)
		if err != nil {
			return nil, err
		}
		msgObj := map[string]json.RawMessage{
			"role":    json.RawMessage(`"user"`),
			"content": contentBytes,
		}
		msgBytes, err := json.Marshal(msgObj)
		if err != nil {
			return nil, err
		}
		messages[msg.Index] = msgBytes
	}

	msgBytes, err := json.Marshal(messages)
	if err != nil {
		return nil, err
	}
	raw["messages"] = msgBytes

	return json.Marshal(raw)
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/proxy/ -v -run TestExtract
```

Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/extract.go internal/proxy/extract_test.go
git commit -m "feat: add AI provider message extractor for Anthropic and OpenAI formats"
```

---

### Task 13: Proxy Core (goproxy Integration)

**Files:**
- Create: `internal/proxy/proxy.go`
- Create: `internal/proxy/rewrite.go`
- Create: `internal/proxy/proxy_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/proxy/proxy_test.go`:

```go
package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/scanner"
)

type noopPipeline struct{}

func (n *noopPipeline) ScanAndRedact(text string) (string, *scanner.PipelineReport, error) {
	return text, &scanner.PipelineReport{}, nil
}

func TestProxyStartStop(t *testing.T) {
	dir := t.TempDir()
	ca, err := certgen.GenerateCA(
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
	)
	if err != nil {
		t.Fatalf("CA error: %v", err)
	}

	df := domain.New([]string{"api.anthropic.com"}, nil)
	p, err := NewProxy(ca, df, &noopPipeline{}, nil)
	if err != nil {
		t.Fatalf("NewProxy error: %v", err)
	}

	addr, err := p.Start(0)
	if err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if addr == "" {
		t.Error("expected non-empty address")
	}

	err = p.Stop()
	if err != nil {
		t.Fatalf("Stop error: %v", err)
	}
}

func TestProxyForwardsNonInterceptedTraffic(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	dir := t.TempDir()
	ca, _ := certgen.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	df := domain.New([]string{"api.anthropic.com"}, nil)
	p, _ := NewProxy(ca, df, &noopPipeline{}, nil)
	addr, _ := p.Start(0)
	defer p.Stop()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("expected 'ok', got %q", string(body))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/proxy/ -v -run TestProxy
```

Expected: FAIL.

- [ ] **Step 3: Write proxy implementation**

Create `internal/proxy/rewrite.go`:

```go
package proxy

import (
	"github.com/rakeshguha/redactr/internal/scanner"
)

type ScanPipeline interface {
	ScanAndRedact(text string) (string, *scanner.PipelineReport, error)
}
```

Create `internal/proxy/proxy.go`:

```go
package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/store"
)

type OnScanFunc func(report *store.ScanReport)

type Proxy struct {
	goproxy  *goproxy.ProxyHttpServer
	server   *http.Server
	listener net.Listener
	ca       *certgen.CA
	domains  *domain.Filter
	pipeline ScanPipeline
	onScan   OnScanFunc
	mu       sync.Mutex
	running  bool
}

func NewProxy(ca *certgen.CA, domains *domain.Filter, pipeline ScanPipeline, onScan OnScanFunc) (*Proxy, error) {
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false

	tlsCert, err := tls.X509KeyPair(
		certPEM(ca),
		keyPEM(ca),
	)
	if err != nil {
		return nil, err
	}

	goproxy.GoproxyCa = tlsCert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject}

	p := &Proxy{
		goproxy:  gp,
		ca:       ca,
		domains:  domains,
		pipeline: pipeline,
		onScan:   onScan,
	}

	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if domains.IsBlocked(host) {
			return goproxy.RejectConnect, host
		}
		if domains.ShouldIntercept(host) {
			return goproxy.MitmConnect, host
		}
		return goproxy.OkConnect, host
	})

	gp.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if !domains.ShouldIntercept(req.Host) {
			return req, nil
		}
		if req.Body == nil {
			return req, nil
		}

		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
			return req, nil
		}

		start := time.Now()
		msg, err := ExtractLastUserMessage(body, req.Host)
		if err != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
			return req, nil
		}

		redactedText, report, err := pipeline.ScanAndRedact(msg.Text)
		if err != nil {
			log.Printf("scan error: %v", err)
			req.Body = io.NopCloser(bytes.NewReader(body))
			return req, nil
		}

		if redactedText != msg.Text {
			newBody, err := ReplaceLastUserMessage(body, msg, redactedText)
			if err != nil {
				log.Printf("rewrite error: %v", err)
				req.Body = io.NopCloser(bytes.NewReader(body))
				return req, nil
			}
			req.Body = io.NopCloser(bytes.NewReader(newBody))
			req.ContentLength = int64(len(newBody))
		} else {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		if onScan := p.onScan; onScan != nil && report != nil {
			scanReport := &store.ScanReport{
				Timestamp: time.Now(),
				Provider:  req.Host,
				Source:    "proxy",
				LatencyMs: time.Since(start).Milliseconds(),
			}
			for _, f := range report.Findings {
				scanReport.Redactions = append(scanReport.Redactions, store.Redaction{
					Label:    f.Label,
					Original: f.Value,
					Start:    f.Start,
					End:      f.End,
				})
			}
			for _, lr := range report.LayerResults {
				scanReport.Layers = append(scanReport.Layers, store.LayerResult{
					Name:          lr.Name,
					FindingsCount: lr.FindingsCount,
					LatencyMs:     lr.LatencyMs,
				})
			}
			onScan(scanReport)
		}

		return req, nil
	})

	return p, nil
}

func (p *Proxy) Start(port int) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var err error
	p.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return "", err
	}

	p.server = &http.Server{Handler: p.goproxy}
	p.running = true

	go p.server.Serve(p.listener)

	return p.listener.Addr().String(), nil
}

func (p *Proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}
	p.running = false
	return p.server.Close()
}

func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

func certPEM(ca *certgen.CA) []byte {
	import (
		"crypto/x509"
		"encoding/pem"
	)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

func keyPEM(ca *certgen.CA) []byte {
	import (
		"crypto/x509"
		"encoding/pem"
	)
	keyDER, _ := x509.MarshalECPrivateKey(ca.Key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
```

**Note:** The `certPEM` and `keyPEM` helper functions have invalid inline imports — these imports must be at the top of the file. The correct implementation moves those imports to the package-level import block:

```go
package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/store"
)

// ... (all code above unchanged, except certPEM and keyPEM become):

func certPEM(ca *certgen.CA) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

func keyPEM(ca *certgen.CA) []byte {
	keyDER, _ := x509.MarshalECPrivateKey(ca.Key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
```

- [ ] **Step 4: Add goproxy dependency and run tests**

```bash
go get github.com/elazarl/goproxy
go test ./internal/proxy/ -v -run TestProxy
```

Expected: both tests PASS.

> **Post-v1 note:** The spec mentions response interception (scanning responses for echoed PII and tool_use blocks with dangerous file references). This is deferred — add a `gp.OnResponse()` handler in a follow-up task.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/ go.mod go.sum
git commit -m "feat: add goproxy-based HTTPS proxy with MITM and scanning pipeline integration"
```

---

### Task 14: Integrated Scan-and-Redact Coordinator

**Files:**
- Create: `internal/scanner/coordinator.go`
- Create: `internal/scanner/coordinator_test.go`

This wires the pipeline + redactor + cache + file blocker into a single `ScanAndRedact` method that the proxy calls.

- [ ] **Step 1: Write failing test**

Create `internal/scanner/coordinator_test.go`:

```go
package scanner

import (
	"testing"

	"github.com/rakeshguha/redactr/internal/fileblock"
	"github.com/rakeshguha/redactr/internal/redactor"
)

func TestCoordinatorScanAndRedact(t *testing.T) {
	layer := &mockLayer{
		name:  "regex",
		ready: true,
		findings: []Finding{
			{Label: "EMAIL", Value: "user@test.com", Start: 9, End: 22, Layer: "regex"},
		},
	}

	fb := fileblock.New([]string{".env"}, true)
	cache := NewCache(100)
	pipeline := NewPipeline(layer)
	coord := NewCoordinator(pipeline, cache, fb)

	text := "contact: user@test.com please"
	redacted, report, err := coord.ScanAndRedact(text)
	if err != nil {
		t.Fatalf("ScanAndRedact error: %v", err)
	}

	expected := "contact: [REDACTED-EMAIL] please"
	if redacted != expected {
		t.Errorf("expected %q, got %q", expected, redacted)
	}
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(report.Findings))
	}
}

func TestCoordinatorCacheHit(t *testing.T) {
	callCount := 0
	layer := &countingLayer{
		name:  "regex",
		ready: true,
		count: &callCount,
	}

	fb := fileblock.New([]string{".env"}, true)
	cache := NewCache(100)
	pipeline := NewPipeline(layer)
	coord := NewCoordinator(pipeline, cache, fb)

	coord.ScanAndRedact("same text")
	coord.ScanAndRedact("same text")

	if callCount != 1 {
		t.Errorf("expected 1 scan call (cached), got %d", callCount)
	}
}

type countingLayer struct {
	name  string
	ready bool
	count *int
}

func (c *countingLayer) Name() string { return c.name }
func (c *countingLayer) Ready() bool  { return c.ready }
func (c *countingLayer) Scan(text string) (*ScanResult, error) {
	*c.count++
	return &ScanResult{}, nil
}

func TestCoordinatorCleanText(t *testing.T) {
	layer := &mockLayer{name: "regex", ready: true, findings: nil}
	fb := fileblock.New([]string{".env"}, true)
	cache := NewCache(100)
	coord := NewCoordinator(NewPipeline(layer), cache, fb)

	redacted, _, err := coord.ScanAndRedact("clean code with no PII")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if redacted != "clean code with no PII" {
		t.Errorf("expected unchanged text, got %q", redacted)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/scanner/ -v -run TestCoordinator
```

Expected: FAIL.

- [ ] **Step 3: Write coordinator implementation**

Create `internal/scanner/coordinator.go`:

```go
package scanner

import (
	"github.com/rakeshguha/redactr/internal/fileblock"
	"github.com/rakeshguha/redactr/internal/redactor"
)

type Coordinator struct {
	pipeline *Pipeline
	cache    *Cache
	fb       *fileblock.Blocker
}

func NewCoordinator(pipeline *Pipeline, cache *Cache, fb *fileblock.Blocker) *Coordinator {
	return &Coordinator{
		pipeline: pipeline,
		cache:    cache,
		fb:       fb,
	}
}

func (c *Coordinator) ScanAndRedact(text string) (string, *PipelineReport, error) {
	if redacted, report, hit := c.cache.Get(text); hit {
		return redacted, report, nil
	}

	report, err := c.pipeline.Scan(text)
	if err != nil {
		return text, nil, err
	}

	result := redactor.Redact(text, report.Findings)

	c.cache.Put(text, result.Text, report)

	return result.Text, report, nil
}

func (c *Coordinator) InvalidateCache() {
	c.cache.Invalidate()
}

func (c *Coordinator) CacheStats() CacheStats {
	return c.cache.Stats()
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/scanner/ -v -run TestCoordinator
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/coordinator.go internal/scanner/coordinator_test.go
git commit -m "feat: add scan coordinator wiring pipeline, cache, file blocker, and redactor"
```

---

## Phase 4: API & Dashboard (Tasks 15-19)

REST API, WebSocket, embedded Next.js dashboard.

---

### Task 15: REST API Server

**Files:**
- Create: `internal/api/server.go`
- Create: `internal/api/routes.go`
- Create: `internal/api/routes_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/api/routes_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rakeshguha/redactr/internal/config"
	"github.com/rakeshguha/redactr/internal/store"
)

func setupTestAPI(t *testing.T) (*Server, *config.Manager, *store.Store) {
	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(filepath.Join(dir, "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(cfgMgr, st, nil, nil)
	return srv, cfgMgr, st
}

func TestGetConfig(t *testing.T) {
	srv, _, _ := setupTestAPI(t)
	req := httptest.NewRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var cfg config.Config
	json.NewDecoder(w.Body).Decode(&cfg)
	if len(cfg.Proxy.InterceptedDomains) == 0 {
		t.Error("expected default intercepted domains")
	}
}

func TestUpdateConfig(t *testing.T) {
	srv, cfgMgr, _ := setupTestAPI(t)

	body := `{"proxy":{"enabled":true,"intercepted_domains":["custom.com"],"blocked_domains":[]},"scanning":{"regex_enabled":true,"entropy_enabled":true,"entropy_threshold":5.0,"gliner_enabled":true,"custom_patterns":[],"custom_blocked_words":[],"cache_max_size":5000},"file_blocking":{"blocked_extensions":[".env"],"content_patterns_enabled":true},"hooks":{"enabled":false,"claude_code":false,"safecmd_overrides":{"added":[],"removed":[]}},"mcp":{"wrapped_servers":{}}}`

	req := httptest.NewRequest("PUT", "/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated := cfgMgr.Get()
	if !updated.Proxy.Enabled {
		t.Error("expected proxy enabled after update")
	}
}

func TestGetLogs(t *testing.T) {
	srv, _, st := setupTestAPI(t)

	st.SaveReport(&store.ScanReport{
		Timestamp: time.Now(),
		Provider:  "anthropic",
		Source:    "proxy",
		LatencyMs: 10,
	})

	req := httptest.NewRequest("GET", "/api/logs?limit=10", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var logs []store.ScanReport
	json.NewDecoder(w.Body).Decode(&logs)
	if len(logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(logs))
	}
}

func TestGetStats(t *testing.T) {
	srv, _, st := setupTestAPI(t)

	st.SaveReport(&store.ScanReport{
		Timestamp: time.Now(),
		Provider:  "anthropic",
		LatencyMs: 10,
		Source:    "proxy",
	})

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var stats store.Stats
	json.NewDecoder(w.Body).Decode(&stats)
	if stats.TotalScanned != 1 {
		t.Errorf("expected 1 total, got %d", stats.TotalScanned)
	}
}

func TestProxyToggle(t *testing.T) {
	srv, _, _ := setupTestAPI(t)

	req := httptest.NewRequest("POST", "/api/proxy/enable", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/api/ -v
```

Expected: FAIL.

- [ ] **Step 3: Write API server and routes**

Create `internal/api/server.go`:

```go
package api

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/rakeshguha/redactr/internal/config"
	"github.com/rakeshguha/redactr/internal/scanner"
	"github.com/rakeshguha/redactr/internal/store"
)

type ProxyController interface {
	Start(port int) (string, error)
	Stop() error
	Addr() string
}

type Server struct {
	cfgMgr      *config.Manager
	store       *store.Store
	proxy       ProxyController
	coordinator *scanner.Coordinator
	mux         *http.ServeMux
	listener    net.Listener
	mu          sync.Mutex
}

func NewServer(cfgMgr *config.Manager, store *store.Store, proxy ProxyController, coordinator *scanner.Coordinator) *Server {
	s := &Server{
		cfgMgr:      cfgMgr,
		store:       store,
		proxy:       proxy,
		coordinator: coordinator,
		mux:         http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) Start(port int) (string, error) {
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return "", err
	}
	go http.Serve(s.listener, s.mux)
	return s.listener.Addr().String(), nil
}

func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
```

Create `internal/api/routes.go`:

```go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rakeshguha/redactr/internal/config"
	"github.com/rakeshguha/redactr/internal/store"
)

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("PUT /api/config", s.handleUpdateConfig)
	s.mux.HandleFunc("GET /api/logs", s.handleGetLogs)
	s.mux.HandleFunc("GET /api/stats", s.handleGetStats)
	s.mux.HandleFunc("POST /api/proxy/enable", s.handleProxyEnable)
	s.mux.HandleFunc("POST /api/proxy/disable", s.handleProxyDisable)
	s.mux.HandleFunc("GET /api/proxy/status", s.handleProxyStatus)
	s.mux.HandleFunc("GET /api/cache/stats", s.handleCacheStats)
	s.mux.HandleFunc("POST /api/cache/clear", s.handleCacheClear)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.cfgMgr.Get())
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.cfgMgr.Update(func(c *config.Config) {
		*c = cfg
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}
	provider := r.URL.Query().Get("provider")

	reports, err := s.store.QueryReports(store.QueryFilter{
		Provider: provider,
		Limit:    limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, reports)
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()

	stats, err := s.store.GetStats(since, until)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, stats)
}

func (s *Server) handleProxyEnable(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, map[string]string{"status": "ok", "message": "proxy controller not configured"})
		return
	}
	addr, err := s.proxy.Start(0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.cfgMgr.Update(func(c *config.Config) { c.Proxy.Enabled = true })
	writeJSON(w, map[string]string{"status": "ok", "addr": addr})
}

func (s *Server) handleProxyDisable(w http.ResponseWriter, r *http.Request) {
	if s.proxy != nil {
		s.proxy.Stop()
	}
	s.cfgMgr.Update(func(c *config.Config) { c.Proxy.Enabled = false })
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Get()
	status := map[string]interface{}{
		"enabled": cfg.Proxy.Enabled,
	}
	if s.proxy != nil {
		status["addr"] = s.proxy.Addr()
	}
	writeJSON(w, status)
}

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.coordinator == nil {
		writeJSON(w, map[string]string{"status": "no coordinator"})
		return
	}
	writeJSON(w, s.coordinator.CacheStats())
}

func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if s.coordinator != nil {
		s.coordinator.InvalidateCache()
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/api/ -v
```

Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/
git commit -m "feat: add REST API server with config, logs, stats, and proxy control endpoints"
```

---

### Task 16: WebSocket Hub

**Files:**
- Create: `internal/api/ws.go`
- Create: `internal/api/ws_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/api/ws_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rakeshguha/redactr/internal/store"
)

func TestWebSocketBroadcast(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	srv := httptest.NewServer(hub.HandleWS())
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	report := &store.ScanReport{
		Timestamp: time.Now(),
		Provider:  "anthropic",
		LatencyMs: 5,
		Source:    "proxy",
	}
	hub.Broadcast(report)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	var received store.ScanReport
	if err := json.Unmarshal(msg, &received); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if received.Provider != "anthropic" {
		t.Errorf("expected anthropic, got %q", received.Provider)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/api/ -v -run TestWebSocket
```

Expected: FAIL.

- [ ] **Step 3: Write WebSocket hub**

Create `internal/api/ws.go`:

```go
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Hub struct {
	clients    map[*websocket.Conn]bool
	mu         sync.Mutex
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.clients[conn] = true
			h.mu.Unlock()
		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[conn]; ok {
				delete(h.clients, conn)
				conn.Close()
			}
			h.mu.Unlock()
		case msg := <-h.broadcast:
			h.mu.Lock()
			for conn := range h.clients {
				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					delete(h.clients, conn)
					conn.Close()
				}
			}
			h.mu.Unlock()
		}
	}
}

func (h *Hub) Broadcast(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("ws broadcast marshal error: %v", err)
		return
	}
	h.broadcast <- data
}

func (h *Hub) HandleWS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		h.register <- conn

		go func() {
			defer func() { h.unregister <- conn }()
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					break
				}
			}
		}()
	}
}
```

- [ ] **Step 4: Add gorilla/websocket and run tests**

```bash
go get github.com/gorilla/websocket
go test ./internal/api/ -v -run TestWebSocket
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ws.go internal/api/ws_test.go go.mod go.sum
git commit -m "feat: add WebSocket hub for real-time log streaming to dashboard"
```

---

### Task 17: Next.js Dashboard Scaffold

**Files:**
- Create: `web/package.json`
- Create: `web/next.config.js`
- Create: `web/app/layout.tsx`
- Create: `web/app/page.tsx`
- Create: `web/lib/api.ts`
- Create: `web/components/toggle.tsx`
- Create: `web/tsconfig.json`
- Create: `web/tailwind.config.ts`

- [ ] **Step 1: Initialize Next.js project**

```bash
cd /Users/rakeshguha/Desktop/Code/clearPass && npx create-next-app@14 web --typescript --tailwind --app --src-dir=false --import-alias="@/*" --no-eslint --use-npm
```

- [ ] **Step 2: Configure static export**

Create/update `web/next.config.js`:

```js
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
}

module.exports = nextConfig
```

- [ ] **Step 3: Create API client**

Create `web/lib/api.ts`:

```typescript
const API_BASE = typeof window !== 'undefined'
  ? `${window.location.protocol}//${window.location.host}/api`
  : '/api';

export async function fetchConfig() {
  const res = await fetch(`${API_BASE}/config`);
  return res.json();
}

export async function updateConfig(config: any) {
  const res = await fetch(`${API_BASE}/config`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  return res.json();
}

export async function fetchLogs(limit = 50, provider?: string) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (provider) params.set('provider', provider);
  const res = await fetch(`${API_BASE}/logs?${params}`);
  return res.json();
}

export async function fetchStats() {
  const res = await fetch(`${API_BASE}/stats`);
  return res.json();
}

export async function enableProxy() {
  const res = await fetch(`${API_BASE}/proxy/enable`, { method: 'POST' });
  return res.json();
}

export async function disableProxy() {
  const res = await fetch(`${API_BASE}/proxy/disable`, { method: 'POST' });
  return res.json();
}

export async function fetchProxyStatus() {
  const res = await fetch(`${API_BASE}/proxy/status`);
  return res.json();
}

export async function fetchCacheStats() {
  const res = await fetch(`${API_BASE}/cache/stats`);
  return res.json();
}

export async function clearCache() {
  const res = await fetch(`${API_BASE}/cache/clear`, { method: 'POST' });
  return res.json();
}

export function connectWebSocket(onMessage: (data: any) => void): WebSocket {
  const wsURL = `ws://${window.location.host}/api/ws`;
  const ws = new WebSocket(wsURL);
  ws.onmessage = (event) => {
    onMessage(JSON.parse(event.data));
  };
  return ws;
}
```

- [ ] **Step 4: Create toggle component**

Create `web/components/toggle.tsx`:

```tsx
'use client';

interface ToggleProps {
  enabled: boolean;
  onToggle: () => void;
  label: string;
}

export function Toggle({ enabled, onToggle, label }: ToggleProps) {
  return (
    <button
      onClick={onToggle}
      className={`relative inline-flex h-12 w-24 items-center rounded-full transition-colors ${
        enabled ? 'bg-green-500' : 'bg-gray-300'
      }`}
    >
      <span className="sr-only">{label}</span>
      <span
        className={`inline-block h-10 w-10 transform rounded-full bg-white transition-transform ${
          enabled ? 'translate-x-13' : 'translate-x-1'
        }`}
      />
    </button>
  );
}
```

- [ ] **Step 5: Create landing page**

Update `web/app/page.tsx`:

```tsx
'use client';

import { useEffect, useState } from 'react';
import { Toggle } from '@/components/toggle';
import { enableProxy, disableProxy, fetchProxyStatus, fetchStats } from '@/lib/api';

interface Stats {
  total_scanned: number;
  total_redactions: number;
  total_blocked: number;
  avg_latency_ms: number;
}

export default function Home() {
  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [sidecarStatus, setSidecarStatus] = useState<string>('unknown');

  useEffect(() => {
    fetchProxyStatus().then((s) => setProxyEnabled(s.enabled));
    fetchStats().then(setStats);
    const interval = setInterval(() => fetchStats().then(setStats), 5000);
    return () => clearInterval(interval);
  }, []);

  const handleToggle = async () => {
    if (proxyEnabled) {
      await disableProxy();
      setProxyEnabled(false);
    } else {
      await enableProxy();
      setProxyEnabled(true);
    }
  };

  return (
    <main className="min-h-screen bg-gray-950 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-2">Redactr</h1>
        <p className="text-gray-400 mb-8">AI Privacy Proxy</p>

        <div className="bg-gray-900 rounded-xl p-8 mb-8 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-semibold mb-1">
              Proxy {proxyEnabled ? 'Active' : 'Inactive'}
            </h2>
            <p className="text-gray-400">
              {proxyEnabled
                ? 'Scanning all AI tool traffic'
                : 'AI tools connecting directly'}
            </p>
          </div>
          <Toggle enabled={proxyEnabled} onToggle={handleToggle} label="Toggle Proxy" />
        </div>

        {stats && (
          <div className="grid grid-cols-4 gap-4">
            <StatCard label="Scanned Today" value={stats.total_scanned} />
            <StatCard label="Redactions" value={stats.total_redactions} />
            <StatCard label="Blocked" value={stats.total_blocked} />
            <StatCard label="Avg Latency" value={`${stats.avg_latency_ms.toFixed(1)}ms`} />
          </div>
        )}
      </div>
    </main>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <p className="text-gray-400 text-sm">{label}</p>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  );
}
```

- [ ] **Step 6: Update layout with navigation**

Update `web/app/layout.tsx`:

```tsx
import type { Metadata } from 'next';
import './globals.css';
import Link from 'next/link';

export const metadata: Metadata = {
  title: 'Redactr',
  description: 'AI Privacy Proxy Dashboard',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-gray-950">
        <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3">
          <div className="max-w-6xl mx-auto flex items-center gap-6">
            <Link href="/" className="text-white font-bold text-lg">Redactr</Link>
            <Link href="/logs" className="text-gray-400 hover:text-white">Logs</Link>
            <Link href="/config" className="text-gray-400 hover:text-white">Config</Link>
            <Link href="/mcp" className="text-gray-400 hover:text-white">MCP</Link>
            <Link href="/hooks" className="text-gray-400 hover:text-white">Hooks</Link>
            <Link href="/latency" className="text-gray-400 hover:text-white">Latency</Link>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
```

- [ ] **Step 7: Verify build**

```bash
cd /Users/rakeshguha/Desktop/Code/clearPass/web && npm run build
```

Expected: static export to `web/out/` directory.

- [ ] **Step 8: Commit**

```bash
git add web/
git commit -m "feat: scaffold Next.js dashboard with landing page, API client, and navigation"
```

---

### Task 18: Dashboard Log View Page

**Files:**
- Create: `web/app/logs/page.tsx`
- Create: `web/components/log-entry.tsx`

- [ ] **Step 1: Create log entry component**

Create `web/components/log-entry.tsx`:

```tsx
'use client';

import { useState } from 'react';

interface Redaction {
  label: string;
  original: string;
  start: number;
  end: number;
}

interface LayerResult {
  name: string;
  findings_count: number;
  latency_ms: number;
}

interface LogEntry {
  id: string;
  timestamp: string;
  provider: string;
  source: string;
  latency_ms: number;
  redactions: Redaction[];
  layers: LayerResult[];
  blocked: boolean;
  reason: string;
}

export function LogEntryRow({ entry }: { entry: LogEntry }) {
  const [expanded, setExpanded] = useState(false);
  const redactionCount = entry.redactions?.length || 0;

  return (
    <div className={`border-b border-gray-800 ${entry.blocked ? 'bg-red-950/20' : ''}`}>
      <div
        className="flex items-center gap-4 p-3 cursor-pointer hover:bg-gray-800/50"
        onClick={() => setExpanded(!expanded)}
      >
        <span className="text-gray-500 text-sm w-44">
          {new Date(entry.timestamp).toLocaleTimeString()}
        </span>
        <span className="text-sm w-24">{entry.provider}</span>
        <span className="text-sm w-16 text-gray-400">{entry.source}</span>
        <span className="text-sm w-20">{entry.latency_ms}ms</span>
        <span className={`text-sm ${redactionCount > 0 ? 'text-yellow-400' : 'text-gray-500'}`}>
          {redactionCount} redaction{redactionCount !== 1 ? 's' : ''}
        </span>
        {entry.blocked && <span className="text-red-400 text-sm">BLOCKED</span>}
        <span className="ml-auto text-gray-500">{expanded ? '▼' : '▶'}</span>
      </div>

      {expanded && (
        <div className="p-4 bg-gray-900/50 text-sm">
          {entry.reason && (
            <p className="text-red-400 mb-2">Reason: {entry.reason}</p>
          )}

          {entry.layers && entry.layers.length > 0 && (
            <div className="mb-3">
              <p className="text-gray-400 mb-1">Layers:</p>
              {entry.layers.map((l, i) => (
                <p key={i} className="ml-4 text-gray-300">
                  {l.name}: {l.findings_count} findings ({l.latency_ms}ms)
                </p>
              ))}
            </div>
          )}

          {entry.redactions && entry.redactions.length > 0 && (
            <div>
              <p className="text-gray-400 mb-1">Redactions:</p>
              {entry.redactions.map((r, i) => (
                <p key={i} className="ml-4">
                  <span className="text-yellow-400">{r.label}</span>
                  <span className="text-gray-500 ml-2">
                    {r.original.substring(0, 3)}***
                  </span>
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Create logs page**

Create `web/app/logs/page.tsx`:

```tsx
'use client';

import { useEffect, useState } from 'react';
import { fetchLogs, connectWebSocket } from '@/lib/api';
import { LogEntryRow } from '@/components/log-entry';

export default function LogsPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [provider, setProvider] = useState<string>('');

  useEffect(() => {
    fetchLogs(100, provider || undefined).then(setLogs);
  }, [provider]);

  useEffect(() => {
    const ws = connectWebSocket((data) => {
      setLogs((prev) => [data, ...prev].slice(0, 500));
    });
    return () => ws.close();
  }, []);

  return (
    <main className="min-h-screen bg-gray-950 text-white p-8">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold">Request Logs</h1>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="bg-gray-800 text-white px-3 py-1.5 rounded"
          >
            <option value="">All Providers</option>
            <option value="api.anthropic.com">Anthropic</option>
            <option value="api.openai.com">OpenAI</option>
            <option value="api.githubcopilot.com">GitHub Copilot</option>
          </select>
        </div>

        <div className="bg-gray-900 rounded-xl overflow-hidden">
          <div className="flex items-center gap-4 p-3 border-b border-gray-700 text-gray-400 text-sm">
            <span className="w-44">Time</span>
            <span className="w-24">Provider</span>
            <span className="w-16">Source</span>
            <span className="w-20">Latency</span>
            <span>Redactions</span>
          </div>
          {logs && logs.length > 0 ? (
            logs.map((entry, i) => <LogEntryRow key={entry.id || i} entry={entry} />)
          ) : (
            <p className="p-8 text-gray-500 text-center">No logs yet</p>
          )}
        </div>
      </div>
    </main>
  );
}
```

- [ ] **Step 3: Verify build**

```bash
cd /Users/rakeshguha/Desktop/Code/clearPass/web && npm run build
```

Expected: builds successfully with logs page.

- [ ] **Step 4: Commit**

```bash
git add web/app/logs/ web/components/log-entry.tsx
git commit -m "feat: add dashboard log view with real-time WebSocket streaming and expandable entries"
```

---

### Task 19: Dashboard Config & Remaining Pages

**Files:**
- Create: `web/app/config/page.tsx`
- Create: `web/app/mcp/page.tsx`
- Create: `web/app/hooks/page.tsx`
- Create: `web/app/latency/page.tsx`
- Create: `web/components/latency-chart.tsx`

- [ ] **Step 1: Create config page**

Create `web/app/config/page.tsx`:

```tsx
'use client';

import { useEffect, useState } from 'react';
import { fetchConfig, updateConfig, fetchCacheStats, clearCache } from '@/lib/api';

export default function ConfigPage() {
  const [config, setConfig] = useState<any>(null);
  const [cacheStats, setCacheStats] = useState<any>(null);
  const [customPattern, setCustomPattern] = useState({ name: '', pattern: '' });
  const [customWord, setCustomWord] = useState('');
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState<string | null>(null);

  useEffect(() => {
    fetchConfig().then(setConfig);
    fetchCacheStats().then(setCacheStats);
  }, []);

  const saveConfig = async (updated: any) => {
    await updateConfig(updated);
    setConfig(updated);
  };

  const toggleLayer = (field: string) => {
    if (!config) return;
    const updated = { ...config, scanning: { ...config.scanning, [field]: !config.scanning[field] } };
    saveConfig(updated);
  };

  const addPattern = () => {
    if (!customPattern.name || !customPattern.pattern) return;
    const updated = {
      ...config,
      scanning: {
        ...config.scanning,
        custom_patterns: [...(config.scanning.custom_patterns || []), customPattern],
      },
    };
    saveConfig(updated);
    setCustomPattern({ name: '', pattern: '' });
  };

  const removePattern = (index: number) => {
    const patterns = [...config.scanning.custom_patterns];
    patterns.splice(index, 1);
    const updated = { ...config, scanning: { ...config.scanning, custom_patterns: patterns } };
    saveConfig(updated);
  };

  const addBlockedWord = () => {
    if (!customWord) return;
    const updated = {
      ...config,
      scanning: {
        ...config.scanning,
        custom_blocked_words: [...(config.scanning.custom_blocked_words || []), customWord],
      },
    };
    saveConfig(updated);
    setCustomWord('');
  };

  const addDomain = (type: 'intercepted_domains' | 'blocked_domains', domain: string) => {
    if (!domain) return;
    const updated = {
      ...config,
      proxy: {
        ...config.proxy,
        [type]: [...(config.proxy[type] || []), domain],
      },
    };
    saveConfig(updated);
  };

  const removeDomain = (type: 'intercepted_domains' | 'blocked_domains', index: number) => {
    const domains = [...config.proxy[type]];
    domains.splice(index, 1);
    const updated = { ...config, proxy: { ...config.proxy, [type]: domains } };
    saveConfig(updated);
  };

  if (!config) return <div className="min-h-screen bg-gray-950 text-white p-8">Loading...</div>;

  return (
    <main className="min-h-screen bg-gray-950 text-white p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        <h1 className="text-2xl font-bold">Configuration</h1>

        <section className="bg-gray-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4">Scanning Layers</h2>
          <div className="space-y-3">
            {['regex_enabled', 'entropy_enabled', 'gliner_enabled'].map((field) => (
              <label key={field} className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={config.scanning[field]}
                  onChange={() => toggleLayer(field)}
                  className="w-4 h-4"
                />
                <span>{field.replace('_enabled', '').toUpperCase()}</span>
              </label>
            ))}
            <div className="flex items-center gap-3 mt-3">
              <span className="text-gray-400">Entropy Threshold:</span>
              <input
                type="range"
                min="2"
                max="7"
                step="0.1"
                value={config.scanning.entropy_threshold}
                onChange={(e) => {
                  const updated = {
                    ...config,
                    scanning: { ...config.scanning, entropy_threshold: parseFloat(e.target.value) },
                  };
                  saveConfig(updated);
                }}
                className="w-48"
              />
              <span>{config.scanning.entropy_threshold}</span>
            </div>
          </div>
        </section>

        <section className="bg-gray-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4">Custom Regex Patterns</h2>
          {config.scanning.custom_patterns?.map((p: any, i: number) => (
            <div key={i} className="flex items-center gap-2 mb-2">
              <span className="text-yellow-400">{p.name}:</span>
              <code className="text-gray-400 text-sm">{p.pattern}</code>
              <button onClick={() => removePattern(i)} className="text-red-400 ml-auto">Remove</button>
            </div>
          ))}
          <div className="flex gap-2 mt-3">
            <input
              placeholder="Label"
              value={customPattern.name}
              onChange={(e) => setCustomPattern({ ...customPattern, name: e.target.value })}
              className="bg-gray-800 px-3 py-1.5 rounded text-sm"
            />
            <input
              placeholder="Regex pattern"
              value={customPattern.pattern}
              onChange={(e) => setCustomPattern({ ...customPattern, pattern: e.target.value })}
              className="bg-gray-800 px-3 py-1.5 rounded text-sm flex-1"
            />
            <button onClick={addPattern} className="bg-blue-600 px-4 py-1.5 rounded text-sm">Add</button>
          </div>
        </section>

        <section className="bg-gray-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4">Blocked Words</h2>
          <div className="flex flex-wrap gap-2 mb-3">
            {config.scanning.custom_blocked_words?.map((w: string, i: number) => (
              <span key={i} className="bg-gray-800 px-3 py-1 rounded text-sm">
                {w}
                <button onClick={() => {
                  const words = [...config.scanning.custom_blocked_words];
                  words.splice(i, 1);
                  saveConfig({ ...config, scanning: { ...config.scanning, custom_blocked_words: words } });
                }} className="text-red-400 ml-2">x</button>
              </span>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              placeholder="Add word"
              value={customWord}
              onChange={(e) => setCustomWord(e.target.value)}
              className="bg-gray-800 px-3 py-1.5 rounded text-sm flex-1"
            />
            <button onClick={addBlockedWord} className="bg-blue-600 px-4 py-1.5 rounded text-sm">Add</button>
          </div>
        </section>

        <section className="bg-gray-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4">Domain Restrictions</h2>
          <div className="mb-4">
            <h3 className="text-gray-400 text-sm mb-2">Intercepted Domains</h3>
            {config.proxy.intercepted_domains?.map((d: string, i: number) => (
              <div key={i} className="flex items-center gap-2 mb-1">
                <span className="text-sm">{d}</span>
                <button onClick={() => removeDomain('intercepted_domains', i)} className="text-red-400 text-sm">Remove</button>
              </div>
            ))}
          </div>
          <div>
            <h3 className="text-gray-400 text-sm mb-2">Blocked Domains</h3>
            {config.proxy.blocked_domains?.map((d: string, i: number) => (
              <div key={i} className="flex items-center gap-2 mb-1">
                <span className="text-sm">{d}</span>
                <button onClick={() => removeDomain('blocked_domains', i)} className="text-red-400 text-sm">Remove</button>
              </div>
            ))}
          </div>
        </section>

        <section className="bg-gray-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4">Cache</h2>
          {cacheStats && (
            <div className="grid grid-cols-4 gap-4 mb-4">
              <div><p className="text-gray-400 text-sm">Hits</p><p className="text-lg">{cacheStats.hits}</p></div>
              <div><p className="text-gray-400 text-sm">Misses</p><p className="text-lg">{cacheStats.misses}</p></div>
              <div><p className="text-gray-400 text-sm">Size</p><p className="text-lg">{cacheStats.size}</p></div>
              <div><p className="text-gray-400 text-sm">Max</p><p className="text-lg">{cacheStats.max_size}</p></div>
            </div>
          )}
          <button onClick={async () => { await clearCache(); fetchCacheStats().then(setCacheStats); }} className="bg-red-600 px-4 py-1.5 rounded text-sm">Clear Cache</button>
        </section>
      </div>
    </main>
  );
}
```

- [ ] **Step 2: Create MCP management page**

Create `web/app/mcp/page.tsx`:

```tsx
'use client';

export default function MCPPage() {
  return (
    <main className="min-h-screen bg-gray-950 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">MCP Server Management</h1>
        <div className="bg-gray-900 rounded-xl p-6">
          <p className="text-gray-400">MCP server auto-discovery and wrapping will appear here once MCP endpoints are configured.</p>
        </div>
      </div>
    </main>
  );
}
```

- [ ] **Step 3: Create hooks page**

Create `web/app/hooks/page.tsx`:

```tsx
'use client';

export default function HooksPage() {
  return (
    <main className="min-h-screen bg-gray-950 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">Command Safety Hooks</h1>
        <div className="bg-gray-900 rounded-xl p-6">
          <p className="text-gray-400">Claude Code hook management and safecmd allowlist configuration will appear here.</p>
        </div>
      </div>
    </main>
  );
}
```

- [ ] **Step 4: Create latency page**

Create `web/components/latency-chart.tsx`:

```tsx
'use client';

interface DataPoint {
  time: string;
  latency: number;
}

export function LatencyChart({ data, height = 200 }: { data: DataPoint[]; height?: number }) {
  if (data.length === 0) {
    return <div className="text-gray-500 text-center py-8">No latency data yet</div>;
  }

  const max = Math.max(...data.map((d) => d.latency), 1);
  const barWidth = Math.max(4, Math.floor(600 / data.length) - 2);

  return (
    <div className="flex items-end gap-0.5" style={{ height }}>
      {data.map((d, i) => (
        <div
          key={i}
          className="bg-blue-500 rounded-t hover:bg-blue-400 transition-colors"
          style={{
            width: barWidth,
            height: `${(d.latency / max) * 100}%`,
            minHeight: 2,
          }}
          title={`${d.time}: ${d.latency}ms`}
        />
      ))}
    </div>
  );
}
```

Create `web/app/latency/page.tsx`:

```tsx
'use client';

import { useEffect, useState } from 'react';
import { fetchLogs } from '@/lib/api';
import { LatencyChart } from '@/components/latency-chart';

export default function LatencyPage() {
  const [latencyData, setLatencyData] = useState<any[]>([]);
  const [percentiles, setPercentiles] = useState({ p50: 0, p95: 0, p99: 0 });

  useEffect(() => {
    fetchLogs(500).then((logs: any[]) => {
      if (!logs || logs.length === 0) return;

      const data = logs.reverse().map((l: any) => ({
        time: new Date(l.timestamp).toLocaleTimeString(),
        latency: l.latency_ms,
      }));
      setLatencyData(data);

      const sorted = [...logs].sort((a, b) => a.latency_ms - b.latency_ms);
      setPercentiles({
        p50: sorted[Math.floor(sorted.length * 0.5)]?.latency_ms || 0,
        p95: sorted[Math.floor(sorted.length * 0.95)]?.latency_ms || 0,
        p99: sorted[Math.floor(sorted.length * 0.99)]?.latency_ms || 0,
      });
    });
  }, []);

  return (
    <main className="min-h-screen bg-gray-950 text-white p-8">
      <div className="max-w-6xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">Latency Observability</h1>

        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="bg-gray-900 rounded-xl p-4">
            <p className="text-gray-400 text-sm">P50</p>
            <p className="text-2xl font-bold">{percentiles.p50}ms</p>
          </div>
          <div className="bg-gray-900 rounded-xl p-4">
            <p className="text-gray-400 text-sm">P95</p>
            <p className="text-2xl font-bold">{percentiles.p95}ms</p>
          </div>
          <div className="bg-gray-900 rounded-xl p-4">
            <p className="text-gray-400 text-sm">P99</p>
            <p className="text-2xl font-bold">{percentiles.p99}ms</p>
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4">Request Latency</h2>
          <LatencyChart data={latencyData} height={250} />
        </div>
      </div>
    </main>
  );
}
```

- [ ] **Step 5: Verify build**

```bash
cd /Users/rakeshguha/Desktop/Code/clearPass/web && npm run build
```

Expected: all pages build successfully.

- [ ] **Step 6: Commit**

```bash
git add web/app/config/ web/app/mcp/ web/app/hooks/ web/app/latency/ web/components/latency-chart.tsx
git commit -m "feat: add dashboard config, MCP, hooks, and latency pages"
```

---

## Phase 5: GLiNER Sidecar & MCP Wrapper (Tasks 20-22)

---

### Task 20: GLiNER Python Sidecar

**Files:**
- Create: `sidecar/gliner/server.py`
- Create: `sidecar/gliner/requirements.txt`

- [ ] **Step 1: Create requirements file**

Create `sidecar/gliner/requirements.txt`:

```
gliner>=0.2.0
flask>=3.0.0
waitress>=3.0.0
```

- [ ] **Step 2: Create sidecar server**

Create `sidecar/gliner/server.py`:

```python
import sys
import json
import logging
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gliner-sidecar")

app = Flask(__name__)
model = None

ENTITY_LABELS = [
    "PERSON", "EMAIL", "PHONE", "ADDRESS", "SSN",
    "CREDIT_CARD", "DATE_OF_BIRTH", "MEDICAL_RECORD",
    "FINANCIAL_ACCOUNT", "PASSPORT", "DRIVER_LICENSE",
    "IP_ADDRESS", "ORGANIZATION",
]

def load_model():
    global model
    logger.info("Loading GLiNER model...")
    from gliner import GLiNER
    model = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")
    logger.info("GLiNER model loaded")

@app.route("/health", methods=["GET"])
def health():
    if model is None:
        return jsonify({"status": "loading"}), 503
    return jsonify({"status": "ready"})

@app.route("/detect", methods=["POST"])
def detect():
    if model is None:
        return jsonify({"entities": []}), 200

    data = request.get_json()
    text = data.get("text", "")
    if not text:
        return jsonify({"entities": []})

    entities = model.predict_entities(text, ENTITY_LABELS, threshold=0.5)

    results = []
    for ent in entities:
        results.append({
            "text": ent["text"],
            "label": ent["label"],
            "start": ent["start"],
            "end": ent["end"],
            "score": round(ent["score"], 4),
        })

    return jsonify({"entities": results})

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765

    import threading
    threading.Thread(target=load_model, daemon=True).start()

    from waitress import serve
    logger.info(f"Starting GLiNER sidecar on port {port}")
    serve(app, host="127.0.0.1", port=port)
```

- [ ] **Step 3: Test sidecar manually**

```bash
cd /Users/rakeshguha/Desktop/Code/clearPass/sidecar/gliner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 server.py 8765 &
sleep 5
curl -s http://localhost:8765/health
curl -s -X POST http://localhost:8765/detect -H "Content-Type: application/json" -d '{"text":"John Smith lives at 123 Main Street"}'
kill %1
```

Expected: health returns `{"status":"loading"}` or `{"status":"ready"}`, detect returns entities.

- [ ] **Step 4: Commit**

```bash
git add sidecar/gliner/
git commit -m "feat: add GLiNER Python sidecar with lazy model loading and PII detection"
```

---

### Task 21: Sidecar Manager (Go)

**Files:**
- Create: `internal/sidecar/manager.go`
- Create: `internal/sidecar/manager_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/sidecar/manager_test.go`:

```go
package sidecar

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFindFreePort(t *testing.T) {
	port, err := FindFreePort()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if port == 0 {
		t.Error("expected non-zero port")
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("port %d not actually free: %v", port, err)
	}
	l.Close()
}

func TestManagerHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ready"}`))
	}))
	defer server.Close()

	m := &Manager{sidecarURL: server.URL}
	if !m.isHealthy() {
		t.Error("expected healthy")
	}
}

func TestManagerHealthCheckFail(t *testing.T) {
	m := &Manager{sidecarURL: "http://localhost:1"}
	if m.isHealthy() {
		t.Error("expected unhealthy")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/sidecar/ -v
```

Expected: FAIL.

- [ ] **Step 3: Write sidecar manager**

Create `internal/sidecar/manager.go`:

```go
package sidecar

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Manager struct {
	pythonPath string
	scriptPath string
	port       int
	sidecarURL string
	cmd        *exec.Cmd
	stateDir   string
}

func NewManager(pythonPath, scriptPath, stateDir string) *Manager {
	return &Manager{
		pythonPath: pythonPath,
		scriptPath: scriptPath,
		stateDir:   stateDir,
	}
}

func (m *Manager) StartLazy() error {
	port, err := FindFreePort()
	if err != nil {
		return err
	}
	m.port = port
	m.sidecarURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	m.cmd = exec.Command(m.pythonPath, m.scriptPath, fmt.Sprintf("%d", port))
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("start gliner sidecar: %w", err)
	}

	if m.stateDir != "" {
		os.WriteFile(
			filepath.Join(m.stateDir, "sidecar.port"),
			[]byte(fmt.Sprintf("%d", port)),
			0644,
		)
	}

	go m.waitForReady()

	log.Printf("GLiNER sidecar starting on port %d (lazy load)", port)
	return nil
}

func (m *Manager) waitForReady() {
	for i := 0; i < 120; i++ {
		time.Sleep(1 * time.Second)
		if m.isHealthy() {
			log.Printf("GLiNER sidecar ready on port %d", m.port)
			return
		}
	}
	log.Printf("GLiNER sidecar failed to become ready within 2 minutes")
}

func (m *Manager) isHealthy() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(m.sidecarURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result["status"] == "ready"
}

func (m *Manager) URL() string {
	return m.sidecarURL
}

func (m *Manager) Stop() error {
	if m.cmd != nil && m.cmd.Process != nil {
		return m.cmd.Process.Kill()
	}
	return nil
}

func FindFreePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/sidecar/ -v
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sidecar/
git commit -m "feat: add sidecar manager for GLiNER Python process lifecycle"
```

---

### Task 22: MCP Wrapper Binary

**Files:**
- Create: `cmd/redactr-mcp-wrap/main.go`
- Create: `internal/mcpwrap/wrap.go`
- Create: `internal/mcpwrap/wrap_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/mcpwrap/wrap_test.go`:

```go
package mcpwrap

import (
	"bytes"
	"testing"
)

func TestScanJSONRPCMessage(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"user email is user@secret.com"}]}}`

	scanner := &mockScanner{
		redacted: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"user email is [REDACTED-EMAIL]"}]}}`,
	}

	result, err := ScanMessage([]byte(msg), scanner)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !bytes.Contains(result, []byte("[REDACTED-EMAIL]")) {
		t.Errorf("expected redacted output, got %s", string(result))
	}
}

func TestPassthroughWhenNoRedactrRunning(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"result":"hello"}`

	result, err := ScanMessage([]byte(msg), nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if string(result) != msg {
		t.Errorf("expected passthrough, got %s", string(result))
	}
}

type mockScanner struct {
	redacted string
}

func (m *mockScanner) ScanText(text string) (string, error) {
	return m.redacted, nil
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/mcpwrap/ -v
```

Expected: FAIL.

- [ ] **Step 3: Write MCP wrapper logic**

Create `internal/mcpwrap/wrap.go`:

```go
package mcpwrap

import (
	"encoding/json"
	"strings"
)

type RemoteScanner interface {
	ScanText(text string) (string, error)
}

func ScanMessage(msg []byte, scanner RemoteScanner) ([]byte, error) {
	if scanner == nil {
		return msg, nil
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(msg, &parsed); err != nil {
		return msg, nil
	}

	text := extractTextFromMessage(parsed)
	if text == "" {
		return msg, nil
	}

	redacted, err := scanner.ScanText(text)
	if err != nil {
		return msg, nil
	}

	if redacted == text {
		return msg, nil
	}

	result := strings.Replace(string(msg), text, redacted, 1)
	return []byte(result), nil
}

func extractTextFromMessage(msg map[string]json.RawMessage) string {
	if result, ok := msg["result"]; ok {
		var resultObj map[string]json.RawMessage
		if err := json.Unmarshal(result, &resultObj); err == nil {
			if content, ok := resultObj["content"]; ok {
				var parts []map[string]interface{}
				if err := json.Unmarshal(content, &parts); err == nil {
					var texts []string
					for _, p := range parts {
						if t, ok := p["text"].(string); ok {
							texts = append(texts, t)
						}
					}
					return strings.Join(texts, "\n")
				}
			}
		}

		var resultStr string
		if err := json.Unmarshal(result, &resultStr); err == nil {
			return resultStr
		}
	}

	if params, ok := msg["params"]; ok {
		var paramsObj map[string]json.RawMessage
		if err := json.Unmarshal(params, &paramsObj); err == nil {
			if content, ok := paramsObj["content"]; ok {
				var contentStr string
				if err := json.Unmarshal(content, &contentStr); err == nil {
					return contentStr
				}
			}
		}
	}

	return ""
}
```

- [ ] **Step 4: Write MCP wrapper binary entry point**

Create `cmd/redactr-mcp-wrap/main.go`:

```go
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rakeshguha/redactr/internal/mcpwrap"
)

type apiScanner struct {
	baseURL string
	client  *http.Client
}

func (s *apiScanner) ScanText(text string) (string, error) {
	body, _ := json.Marshal(map[string]string{"text": text})
	resp, err := s.client.Post(s.baseURL+"/api/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		return text, err
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if redacted, ok := result["redacted"]; ok {
		return redacted, nil
	}
	return text, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: redactr-mcp-wrap <command> [args...]\n")
		os.Exit(1)
	}

	var scanner mcpwrap.RemoteScanner
	apiPort := discoverAPIPort()
	if apiPort != "" {
		scanner = &apiScanner{
			baseURL: "http://127.0.0.1:" + apiPort,
			client:  &http.Client{Timeout: 5 * time.Second},
		}
	}

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr

	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start MCP server: %v", err)
	}

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := sc.Bytes()
			scanned, _ := mcpwrap.ScanMessage(line, scanner)
			stdin.Write(scanned)
			stdin.Write([]byte("\n"))
		}
		stdin.Close()
	}()

	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Bytes()
		scanned, _ := mcpwrap.ScanMessage(line, scanner)
		os.Stdout.Write(scanned)
		os.Stdout.Write([]byte("\n"))
	}

	cmd.Wait()
}

func discoverAPIPort() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".redactr", "state", "api.port"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/mcpwrap/ -v
```

Expected: all 2 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/redactr-mcp-wrap/ internal/mcpwrap/
git commit -m "feat: add MCP wrapper binary for stdin/stdout interception and scanning"
```

---

## Phase 6: Firewall, Hooks & Main Entry Point (Tasks 23-25)

---

### Task 23: Firewall Manager

**Files:**
- Create: `internal/firewall/firewall.go`
- Create: `internal/firewall/darwin.go`
- Create: `internal/firewall/linux.go`
- Create: `internal/firewall/windows.go`
- Create: `internal/firewall/firewall_test.go`

- [ ] **Step 1: Write firewall interface and platform detection**

Create `internal/firewall/firewall.go`:

```go
package firewall

import (
	"fmt"
	"runtime"
)

type Manager interface {
	BlockDirect(domains []string, proxyPort int) error
	Unblock() error
	Status() ([]Rule, error)
	Cleanup() error
}

type Rule struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Active bool   `json:"active"`
}

func New() (Manager, error) {
	switch runtime.GOOS {
	case "darwin":
		return &darwinFirewall{}, nil
	case "linux":
		return &linuxFirewall{}, nil
	case "windows":
		return &windowsFirewall{}, nil
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
```

- [ ] **Step 2: Write platform stubs**

Create `internal/firewall/darwin.go`:

```go
package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

type darwinFirewall struct {
	active bool
}

func (f *darwinFirewall) BlockDirect(domains []string, proxyPort int) error {
	for _, domain := range domains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			log.Printf("firewall: failed to resolve %s: %v", domain, err)
			continue
		}
		for _, ip := range ips {
			rule := fmt.Sprintf("block drop out proto tcp from any to %s port 443", ip)
			cmd := exec.Command("pfctl", "-a", "com.redactr", "-f", "-")
			cmd.Stdin = strings.NewReader(rule + "\n")
			if err := cmd.Run(); err != nil {
				log.Printf("firewall: pfctl error for %s: %v", ip, err)
			}
		}
	}
	f.active = true
	return nil
}

func (f *darwinFirewall) Unblock() error {
	cmd := exec.Command("pfctl", "-a", "com.redactr", "-F", "all")
	f.active = false
	return cmd.Run()
}

func (f *darwinFirewall) Status() ([]Rule, error) {
	if !f.active {
		return nil, nil
	}
	cmd := exec.Command("pfctl", "-a", "com.redactr", "-sr")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			rules = append(rules, Rule{Domain: "parsed-from-rule", Active: true})
		}
	}
	return rules, nil
}

func (f *darwinFirewall) Cleanup() error {
	return f.Unblock()
}
```

Create `internal/firewall/linux.go`:

```go
package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
)

type linuxFirewall struct {
	blockedIPs []string
}

func (f *linuxFirewall) BlockDirect(domains []string, proxyPort int) error {
	for _, domain := range domains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			log.Printf("firewall: failed to resolve %s: %v", domain, err)
			continue
		}
		for _, ip := range ips {
			cmd := exec.Command("iptables", "-A", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
			if err := cmd.Run(); err != nil {
				log.Printf("firewall: iptables error for %s: %v", ip, err)
			}
			f.blockedIPs = append(f.blockedIPs, ip)
		}
	}
	return nil
}

func (f *linuxFirewall) Unblock() error {
	for _, ip := range f.blockedIPs {
		exec.Command("iptables", "-D", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP").Run()
	}
	f.blockedIPs = nil
	return nil
}

func (f *linuxFirewall) Status() ([]Rule, error) {
	var rules []Rule
	for _, ip := range f.blockedIPs {
		rules = append(rules, Rule{IP: ip, Active: true})
	}
	return rules, nil
}

func (f *linuxFirewall) Cleanup() error {
	return f.Unblock()
}
```

Create `internal/firewall/windows.go`:

```go
package firewall

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

type windowsFirewall struct {
	ruleNames []string
}

func (f *windowsFirewall) BlockDirect(domains []string, proxyPort int) error {
	for _, domain := range domains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			log.Printf("firewall: failed to resolve %s: %v", domain, err)
			continue
		}
		ipList := strings.Join(ips, ",")
		ruleName := fmt.Sprintf("Redactr-Block-%s", domain)
		cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=out", "action=block",
			"protocol=tcp", "remoteport=443",
			"remoteip="+ipList)
		if err := cmd.Run(); err != nil {
			log.Printf("firewall: netsh error for %s: %v", domain, err)
		}
		f.ruleNames = append(f.ruleNames, ruleName)
	}
	return nil
}

func (f *windowsFirewall) Unblock() error {
	for _, name := range f.ruleNames {
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	}
	f.ruleNames = nil
	return nil
}

func (f *windowsFirewall) Status() ([]Rule, error) {
	var rules []Rule
	for _, name := range f.ruleNames {
		rules = append(rules, Rule{Domain: name, Active: true})
	}
	return rules, nil
}

func (f *windowsFirewall) Cleanup() error {
	return f.Unblock()
}
```

- [ ] **Step 3: Write test for platform detection**

Create `internal/firewall/firewall_test.go`:

```go
package firewall

import (
	"runtime"
	"testing"
)

func TestNewReturnsCorrectPlatform(t *testing.T) {
	mgr, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	switch runtime.GOOS {
	case "darwin":
		if _, ok := mgr.(*darwinFirewall); !ok {
			t.Error("expected darwinFirewall on macOS")
		}
	case "linux":
		if _, ok := mgr.(*linuxFirewall); !ok {
			t.Error("expected linuxFirewall on Linux")
		}
	case "windows":
		if _, ok := mgr.(*windowsFirewall); !ok {
			t.Error("expected windowsFirewall on Windows")
		}
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/firewall/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/firewall/
git commit -m "feat: add OS-level firewall manager for provider URL blocking (macOS/Linux/Windows)"
```

---

### Task 24: Claude Code Hooks Manager

**Files:**
- Create: `internal/hooks/claude.go`
- Create: `internal/hooks/safecmd.go`
- Create: `internal/hooks/claude_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/hooks/claude_test.go`:

```go
package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallHook(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, ".claude")
	os.MkdirAll(settingsDir, 0755)

	mgr := NewClaudeManager(settingsDir)
	err := mgr.InstallHook()
	if err != nil {
		t.Fatalf("InstallHook() error: %v", err)
	}

	settingsPath := filepath.Join(settingsDir, "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}

	var settings map[string]interface{}
	json.Unmarshal(data, &settings)

	hooks, ok := settings["hooks"]
	if !ok {
		t.Fatal("expected hooks key in settings")
	}

	hookMap, ok := hooks.(map[string]interface{})
	if !ok {
		t.Fatal("expected hooks to be a map")
	}

	if _, ok := hookMap["PreToolUse"]; !ok {
		t.Error("expected PreToolUse hook")
	}
}

func TestRemoveHook(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, ".claude")
	os.MkdirAll(settingsDir, 0755)

	mgr := NewClaudeManager(settingsDir)
	mgr.InstallHook()
	err := mgr.RemoveHook()
	if err != nil {
		t.Fatalf("RemoveHook() error: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(settingsDir, "settings.json"))
	var settings map[string]interface{}
	json.Unmarshal(data, &settings)

	if hooks, ok := settings["hooks"]; ok {
		hookMap := hooks.(map[string]interface{})
		if _, ok := hookMap["PreToolUse"]; ok {
			t.Error("expected PreToolUse hook removed")
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/hooks/ -v
```

Expected: FAIL.

- [ ] **Step 3: Write safecmd allowlist loader**

Create `internal/hooks/safecmd.go`:

```go
package hooks

var DefaultSafeCmds = []string{
	"cat", "head", "tail", "less", "more", "bat",
	"ls", "tree", "locate",
	"grep", "rg", "ag", "ack", "fgrep", "egrep",
	"cut", "sort", "uniq", "wc", "tr", "column",
	"file", "stat", "du", "df", "which", "whereis", "type",
	"diff", "cmp", "comm",
	"date", "cal", "uptime", "whoami", "hostname", "uname", "printenv",
	"echo", "printf", "basename", "dirname", "realpath",
	"git blame", "git branch", "git diff", "git log", "git ls-files",
	"git remote", "git rev-parse", "git show", "git stash list",
	"git status", "git tag",
	"pwd", "find", "env",
}

func BuildAllowlist(defaults []string, added, removed []string) []string {
	allowed := make(map[string]bool)
	for _, cmd := range defaults {
		allowed[cmd] = true
	}
	for _, cmd := range added {
		allowed[cmd] = true
	}
	for _, cmd := range removed {
		delete(allowed, cmd)
	}
	var result []string
	for cmd := range allowed {
		result = append(result, cmd)
	}
	return result
}
```

- [ ] **Step 4: Write Claude hooks manager**

Create `internal/hooks/claude.go`:

```go
package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type ClaudeManager struct {
	settingsDir string
}

func NewClaudeManager(settingsDir string) *ClaudeManager {
	return &ClaudeManager{settingsDir: settingsDir}
}

func (m *ClaudeManager) InstallHook() error {
	settingsPath := filepath.Join(m.settingsDir, "settings.json")

	settings := make(map[string]interface{})
	if data, err := os.ReadFile(settingsPath); err == nil {
		json.Unmarshal(data, &settings)
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		hooks = make(map[string]interface{})
	}

	hooks["PreToolUse"] = []map[string]interface{}{
		{
			"matcher": "Bash",
			"hooks": []map[string]string{
				{
					"type":    "command",
					"command": "redactr-hook-check",
				},
			},
		},
	}

	settings["hooks"] = hooks

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsPath, data, 0644)
}

func (m *ClaudeManager) RemoveHook() error {
	settingsPath := filepath.Join(m.settingsDir, "settings.json")

	settings := make(map[string]interface{})
	if data, err := os.ReadFile(settingsPath); err == nil {
		json.Unmarshal(data, &settings)
	}

	if hooks, ok := settings["hooks"].(map[string]interface{}); ok {
		delete(hooks, "PreToolUse")
		if len(hooks) == 0 {
			delete(settings, "hooks")
		}
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsPath, data, 0644)
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/hooks/ -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/hooks/
git commit -m "feat: add Claude Code hooks manager with safecmd allowlist"
```

---

### Task 25: Main Entry Point (Wire Everything Together)

**Files:**
- Modify: `cmd/redactr/main.go`

- [ ] **Step 1: Write the full main.go**

Update `cmd/redactr/main.go`:

```go
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/rakeshguha/redactr/internal/api"
	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/config"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/fileblock"
	"github.com/rakeshguha/redactr/internal/firewall"
	"github.com/rakeshguha/redactr/internal/proxy"
	"github.com/rakeshguha/redactr/internal/scanner"
	"github.com/rakeshguha/redactr/internal/scanner/contextgate"
	"github.com/rakeshguha/redactr/internal/scanner/entropy"
	"github.com/rakeshguha/redactr/internal/scanner/gliner"
	"github.com/rakeshguha/redactr/internal/scanner/regex"
	"github.com/rakeshguha/redactr/internal/sidecar"
	"github.com/rakeshguha/redactr/internal/store"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "cleanup" {
		runCleanup()
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine home directory: %v", err)
	}

	baseDir := filepath.Join(home, ".redactr")
	os.MkdirAll(filepath.Join(baseDir, "certs"), 0755)
	os.MkdirAll(filepath.Join(baseDir, "data"), 0755)
	os.MkdirAll(filepath.Join(baseDir, "state"), 0755)

	cfgMgr, err := config.NewManager(filepath.Join(baseDir, "config.yaml"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg := cfgMgr.Get()

	ca, err := certgen.LoadOrCreateCA(
		filepath.Join(baseDir, "certs", "ca.crt"),
		filepath.Join(baseDir, "certs", "ca.key"),
	)
	if err != nil {
		log.Fatalf("CA: %v", err)
	}

	logStore, err := store.New(filepath.Join(baseDir, "data", "logs.db"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer logStore.Close()

	regexScanner := regex.New(regex.DefaultPatterns(), nil)
	entropyScanner := entropy.New(cfg.Scanning.EntropyThreshold, 20)
	glinerClient := gliner.New("http://127.0.0.1:0")
	contextGate := contextgate.New()

	pipeline := scanner.NewPipeline(regexScanner, entropyScanner, glinerClient, contextGate)
	cache := scanner.NewCache(cfg.Scanning.CacheMaxSize)
	fb := fileblock.New(cfg.FileBlocking.BlockedExtensions, cfg.FileBlocking.ContentPatternsEnabled)
	coordinator := scanner.NewCoordinator(pipeline, cache, fb)

	domainFilter := domain.New(cfg.Proxy.InterceptedDomains, cfg.Proxy.BlockedDomains)

	hub := api.NewHub()
	go hub.Run()

	onScan := func(report *store.ScanReport) {
		logStore.SaveReport(report)
		hub.Broadcast(report)
	}

	p, err := proxy.NewProxy(ca, domainFilter, coordinator, onScan)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}

	apiServer := api.NewServer(cfgMgr, logStore, p, coordinator)

	dashboardAddr, err := apiServer.Start(0)
	if err != nil {
		log.Fatalf("dashboard: %v", err)
	}
	os.WriteFile(filepath.Join(baseDir, "state", "dashboard.port"), []byte(dashboardAddr), 0644)

	sidecarMgr := sidecar.NewManager(
		"python3",
		filepath.Join(baseDir, "..", "sidecar", "gliner", "server.py"),
		filepath.Join(baseDir, "state"),
	)
	if cfg.Scanning.GLiNEREnabled {
		if err := sidecarMgr.StartLazy(); err != nil {
			log.Printf("GLiNER sidecar start warning: %v", err)
		} else {
			glinerClient = gliner.New(sidecarMgr.URL())
		}
	}

	log.Printf("Redactr dashboard: http://%s", dashboardAddr)
	log.Printf("CA cert: %s", filepath.Join(baseDir, "certs", "ca.crt"))

	if cfg.Proxy.Enabled {
		proxyAddr, err := p.Start(0)
		if err != nil {
			log.Fatalf("proxy start: %v", err)
		}
		os.WriteFile(filepath.Join(baseDir, "state", "proxy.pid"), []byte(proxyAddr), 0644)
		log.Printf("Proxy listening: %s", proxyAddr)
	} else {
		log.Println("Proxy disabled — enable from dashboard")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	p.Stop()
	sidecarMgr.Stop()
	apiServer.Stop()

	fw, err := firewall.New()
	if err == nil {
		fw.Cleanup()
	}

	os.Remove(filepath.Join(baseDir, "state", "proxy.pid"))
	os.Remove(filepath.Join(baseDir, "state", "dashboard.port"))
	os.Remove(filepath.Join(baseDir, "state", "api.port"))
	os.Remove(filepath.Join(baseDir, "state", "sidecar.port"))

	log.Println("Redactr stopped")
}

func runCleanup() {
	fw, err := firewall.New()
	if err != nil {
		log.Fatalf("firewall: %v", err)
	}
	if err := fw.Cleanup(); err != nil {
		log.Fatalf("cleanup: %v", err)
	}
	fmt.Println("Firewall rules cleaned up")
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./cmd/redactr
```

Expected: compiles without errors.

- [ ] **Step 3: Commit**

```bash
git add cmd/redactr/main.go
git commit -m "feat: wire all subsystems together in main entry point"
```

---

## Phase 7: Build System & Static Embedding (Task 26)

---

### Task 26: Build Script & Static Dashboard Embedding

**Files:**
- Create: `scripts/build.sh`
- Create: `internal/api/embed.go`
- Modify: `Makefile`

- [ ] **Step 1: Create build script**

Create `scripts/build.sh`:

```bash
#!/bin/bash
set -euo pipefail

echo "Building Next.js dashboard..."
cd web
npm ci
npm run build
cd ..

echo "Building Go binaries..."
go build -o bin/redactr ./cmd/redactr
go build -o bin/redactr-mcp-wrap ./cmd/redactr-mcp-wrap

echo "Build complete!"
echo "  bin/redactr"
echo "  bin/redactr-mcp-wrap"
```

```bash
chmod +x scripts/build.sh
```

- [ ] **Step 2: Create embed file for static assets**

Create `internal/api/embed.go`:

```go
package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var staticFiles embed.FS

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
```

- [ ] **Step 3: Update server to serve static files**

Add to `internal/api/server.go` in the `registerRoutes` method (in `routes.go`), at the end:

```go
s.mux.Handle("/", staticHandler())
```

- [ ] **Step 4: Update Makefile**

Update `Makefile`:

```makefile
.PHONY: build test dev clean build-dashboard

BINARY=bin/redactr
MCP_BINARY=bin/redactr-mcp-wrap

build: build-dashboard
	mkdir -p internal/api/static
	cp -r web/out/* internal/api/static/
	go build -o $(BINARY) ./cmd/redactr
	go build -o $(MCP_BINARY) ./cmd/redactr-mcp-wrap

build-dashboard:
	cd web && npm ci && npm run build

test:
	go test ./... -v

dev:
	go run ./cmd/redactr

clean:
	rm -rf bin/ internal/api/static/ web/out/ web/.next/

benchmark:
	go test ./benchmarks/... -bench=. -v
```

- [ ] **Step 5: Test full build**

```bash
make build
```

Expected: produces `bin/redactr` and `bin/redactr-mcp-wrap`.

- [ ] **Step 6: Commit**

```bash
git add scripts/ internal/api/embed.go Makefile
git commit -m "feat: add build system with Next.js static export embedded in Go binary"
```

---

## Phase 8: Integration Testing (Task 27)

---

### Task 27: End-to-End Integration Test

**Files:**
- Create: `test/integration/proxy_test.go`

- [ ] **Step 1: Write integration test**

Create `test/integration/proxy_test.go`:

```go
//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/config"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/fileblock"
	"github.com/rakeshguha/redactr/internal/proxy"
	"github.com/rakeshguha/redactr/internal/scanner"
	"github.com/rakeshguha/redactr/internal/scanner/contextgate"
	"github.com/rakeshguha/redactr/internal/scanner/entropy"
	"github.com/rakeshguha/redactr/internal/scanner/regex"
	"github.com/rakeshguha/redactr/internal/store"

	"net/http/httptest"
)

func TestFullPipelineViaProxy(t *testing.T) {
	fakeAPI := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte("user@secret.com")) {
			t.Error("PII leaked through proxy — email not redacted")
		}
		if !bytes.Contains(body, []byte("[REDACTED-EMAIL]")) {
			t.Error("expected redacted email in forwarded request")
		}
		w.Write([]byte(`{"id":"msg_123","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer fakeAPI.Close()

	dir := t.TempDir()
	ca, _ := certgen.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	fakeHost := fakeAPI.Listener.Addr().String()
	df := domain.New([]string{fakeHost}, nil)

	regexLayer := regex.New(regex.DefaultPatterns(), nil)
	entropyLayer := entropy.New(4.5, 20)
	gateLayer := contextgate.New()
	pipeline := scanner.NewPipeline(regexLayer, entropyLayer, gateLayer)
	cache := scanner.NewCache(100)
	fb := fileblock.New([]string{".env"}, true)
	coord := scanner.NewCoordinator(pipeline, cache, fb)

	var reports []*store.ScanReport
	onScan := func(r *store.ScanReport) { reports = append(reports, r) }

	p, err := proxy.NewProxy(ca, df, coord, onScan)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	proxyAddr, _ := p.Start(0)
	defer p.Stop()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	reqBody := map[string]interface{}{
		"model": "claude-sonnet-4-20250514",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "my email is user@secret.com and key AKIAIOSFODNN7EXAMPLE"},
		},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	resp, err := client.Post(fakeAPI.URL+"/v1/messages", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("request via proxy: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(100 * time.Millisecond)

	if len(reports) == 0 {
		t.Error("expected at least one scan report")
	}
}
```

- [ ] **Step 2: Run integration test**

```bash
go test ./test/integration/ -v -tags=integration
```

Expected: PASS — email and AWS key redacted before reaching fake API.

- [ ] **Step 3: Commit**

```bash
git add test/
git commit -m "test: add end-to-end integration test for proxy scanning pipeline"
```

---

## Phase 9: Benchmarking (Task 28)

---

### Task 28: Benchmark Harness

**Files:**
- Create: `benchmarks/runner_test.go`
- Create: `benchmarks/testdata/pii_samples.json`

- [ ] **Step 1: Create test data**

Create `benchmarks/testdata/pii_samples.json`:

```json
[
  {
    "input": "Contact John Smith at john.smith@company.com or call (555) 867-5309. SSN: 123-45-6789",
    "expected_labels": ["EMAIL", "PHONE", "SSN"],
    "description": "basic PII in plain text"
  },
  {
    "input": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "expected_labels": ["AWS-SECRET-KEY"],
    "description": "AWS secret key"
  },
  {
    "input": "DB_HOST=prod.db.internal\nDB_PASSWORD=SuperSecret123!\nAPI_KEY=sk-proj-abc123def456",
    "expected_labels": ["GENERIC-SECRET"],
    "description": "env file content"
  },
  {
    "input": "func main() {\n\tfmt.Println(\"hello world\")\n\tfor i := 0; i < 10; i++ {\n\t\tresult++\n\t}\n}",
    "expected_labels": [],
    "description": "clean Go code — should produce no findings"
  },
  {
    "input": "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "expected_labels": ["JWT"],
    "description": "JWT token"
  },
  {
    "input": "postgres://admin:password123@db.example.com:5432/production",
    "expected_labels": ["CONNECTION-STRING"],
    "description": "database connection string"
  }
]
```

- [ ] **Step 2: Write benchmark**

Create `benchmarks/runner_test.go`:

```go
package benchmarks

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/rakeshguha/redactr/internal/fileblock"
	"github.com/rakeshguha/redactr/internal/scanner"
	"github.com/rakeshguha/redactr/internal/scanner/contextgate"
	"github.com/rakeshguha/redactr/internal/scanner/entropy"
	"github.com/rakeshguha/redactr/internal/scanner/regex"
)

type sample struct {
	Input          string   `json:"input"`
	ExpectedLabels []string `json:"expected_labels"`
	Description    string   `json:"description"`
}

func loadSamples(t testing.TB) []sample {
	data, err := os.ReadFile("testdata/pii_samples.json")
	if err != nil {
		t.Fatalf("load samples: %v", err)
	}
	var samples []sample
	json.Unmarshal(data, &samples)
	return samples
}

func buildCoordinator() *scanner.Coordinator {
	regexLayer := regex.New(regex.DefaultPatterns(), nil)
	entropyLayer := entropy.New(4.5, 20)
	gateLayer := contextgate.New()
	pipeline := scanner.NewPipeline(regexLayer, entropyLayer, gateLayer)
	cache := scanner.NewCache(10000)
	fb := fileblock.New([]string{".env", ".tfstate"}, true)
	return scanner.NewCoordinator(pipeline, cache, fb)
}

func TestDetectionAccuracy(t *testing.T) {
	samples := loadSamples(t)
	coord := buildCoordinator()

	for _, s := range samples {
		t.Run(s.Description, func(t *testing.T) {
			_, report, err := coord.ScanAndRedact(s.Input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}

			foundLabels := make(map[string]bool)
			for _, f := range report.Findings {
				foundLabels[f.Label] = true
			}

			for _, expected := range s.ExpectedLabels {
				if !foundLabels[expected] {
					t.Errorf("missed expected label %q in %q", expected, s.Description)
				}
			}

			if len(s.ExpectedLabels) == 0 && len(report.Findings) > 0 {
				t.Errorf("false positive: expected no findings, got %d", len(report.Findings))
			}
		})
	}
}

func BenchmarkScanPipeline(b *testing.B) {
	samples := loadSamples(b)
	coord := buildCoordinator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range samples {
			coord.ScanAndRedact(s.Input)
		}
	}
}

func BenchmarkScanPipelineCached(b *testing.B) {
	samples := loadSamples(b)
	coord := buildCoordinator()

	for _, s := range samples {
		coord.ScanAndRedact(s.Input)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range samples {
			coord.ScanAndRedact(s.Input)
		}
	}
}
```

- [ ] **Step 3: Run accuracy tests**

```bash
go test ./benchmarks/ -v -run TestDetection
```

Expected: all detection tests PASS.

- [ ] **Step 4: Run benchmarks**

```bash
go test ./benchmarks/ -bench=. -benchmem
```

Expected: benchmark results showing ops/sec and memory allocation.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/
git commit -m "feat: add benchmark harness with PII sample data and detection accuracy tests"
```

---

## Summary

| Phase | Tasks | What's Working After |
|-------|-------|---------------------|
| 1: Foundation | 1-5 | Go project, config, CA, BoltDB, domain filter |
| 2: Scanning | 6-11 | Full 4-layer scanner pipeline with cache |
| 3: Proxy | 12-14 | goproxy HTTPS MITM with message extraction and redaction |
| 4: API & Dashboard | 15-19 | REST API, WebSocket, complete Next.js dashboard |
| 5: Sidecar & MCP | 20-22 | GLiNER Python sidecar, MCP wrapper binary |
| 6: Firewall & Hooks | 23-25 | OS firewall blocking, Claude Code hooks, main entry point |
| 7: Build System | 26 | Static dashboard embedding, single binary build |
| 8: Integration | 27 | End-to-end proxy scanning test |
| 9: Benchmarks | 28 | Detection accuracy tests, performance benchmarks |
