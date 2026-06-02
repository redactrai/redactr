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
	Logging      LoggingConfig      `yaml:"logging"`
	Admin        AdminConfig        `yaml:"admin"`
	Licensing    LicensingConfig    `yaml:"licensing"`
}

type AdminConfig struct {
	Port int `yaml:"port"`
}

type LicensingConfig struct {
	Key string `yaml:"key"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

type ProxyConfig struct {
	Enabled            bool     `yaml:"enabled"`
	InterceptedDomains []string `yaml:"intercepted_domains"`
	BlockedDomains     []string `yaml:"blocked_domains"`
}

type BypassRule struct {
	Path   string `yaml:"path,omitempty"`
	Prefix string `yaml:"prefix,omitempty"`
	Method string `yaml:"method,omitempty"`
}

type ScanningConfig struct {
	InferenceTimeoutMs int             `yaml:"inference_timeout_ms"`
	EntropyThreshold   float64         `yaml:"entropy_threshold"`
	CustomPatterns     []CustomPattern `yaml:"custom_patterns"`
	CustomBlockedWords []string        `yaml:"custom_blocked_words"`
	AllowedWords       []string        `yaml:"allowed_words"`
	Bypass             []BypassRule    `yaml:"bypass"`
	CacheMaxSize       int             `yaml:"cache_max_size"`

	// Rules holds per-rule toggle state. Keys are rule IDs from
	// internal/rules; missing keys fall back to tier defaults.
	Rules map[string]bool `yaml:"rules,omitempty"`

	// Migrated is set to true after MigrateLegacyLayerFlagsFromFile runs
	// once, so subsequent loads do not re-migrate.
	Migrated bool `yaml:"migrated,omitempty"`
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

func (m *Manager) Reload() (*Config, error) {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	m.mu.Lock()
	old := m.cfg
	m.cfg = cfg
	m.mu.Unlock()
	_ = old
	return cfg, nil
}

func (m *Manager) Path() string {
	return m.path
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
