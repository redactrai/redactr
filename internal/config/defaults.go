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
			InferenceTimeoutMs: 5000,
			EntropyThreshold:   4.5,
			CustomPatterns:     []CustomPattern{},
			CustomBlockedWords: []string{},
			Bypass: []BypassRule{
				{Path: "/v1/models"},
				{Prefix: "/.well-known/"},
				{Method: "OPTIONS"},
			},
			CacheMaxSize: 10000,
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
		Admin: AdminConfig{
			Port: 9090,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Output: "stdout",
		},
	}
}
