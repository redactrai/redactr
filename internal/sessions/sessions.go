// Package sessions discovers running AI-tool processes (Claude Code, Codex,
// Cursor, etc.), classifies each as protected or runaway, and exposes
// operations to remediate runaway sessions.
package sessions

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	StatusProtected Status = "protected"
	StatusRunaway   Status = "runaway"
	StatusUnknown   Status = "unknown"
)

const (
	BoundEnvKey   = "REDACTR_BOUND"
	BoundEnvValue = "1"
)

// Session is a discovered AI-tool process plus its routing posture.
type Session struct {
	PID          int       `json:"pid"`
	PPID         int       `json:"ppid"`
	User         string    `json:"user"`
	Command      string    `json:"command"`
	Tool         string    `json:"tool"`
	StartedAt    time.Time `json:"started_at"`
	Status       Status    `json:"status"`
	Reason       string    `json:"reason"`
	HasProxyEnv  bool      `json:"has_proxy_env"`
	ProxyEnv     string    `json:"proxy_env,omitempty"`
	BoundFlag    bool      `json:"bound_flag"`
	Connections  []string  `json:"connections"`
	DirectAIConn []string  `json:"direct_ai_conn,omitempty"`
	ViaProxy     bool      `json:"via_proxy"`
}

// AITool maps a binary basename or prefix to a friendly label.
var aiTools = []struct {
	Match string
	Label string
}{
	{"claude", "Claude Code"},
	{"codex", "OpenAI Codex"},
	{"cursor", "Cursor"},
	{"windsurf", "Windsurf"},
	{"continue", "Continue"},
	{"aider", "Aider"},
	{"gemini", "Gemini CLI"},
	{"copilot", "GitHub Copilot CLI"},
}

// AIHosts is the default set of upstream AI provider hostnames whose direct
// connections imply a runaway session.
var AIHosts = []string{
	"api.anthropic.com",
	"api.openai.com",
	"api.githubcopilot.com",
	"copilot-proxy.githubusercontent.com",
	"generativelanguage.googleapis.com",
	"api.mistral.ai",
	"api.cohere.ai",
}

// Lister discovers and classifies AI-tool sessions.
type Lister struct {
	mu          sync.RWMutex
	proxyAddr   string
	aiHosts     []string
	hostIPs     map[string]bool
	hostIPsAt   time.Time
	currentPID  int
}

func New(currentPID int) *Lister {
	return &Lister{
		aiHosts:    append([]string{}, AIHosts...),
		hostIPs:    make(map[string]bool),
		currentPID: currentPID,
	}
}

// SetProxyAddr records the address of the local Redactr proxy. Connections
// to this address indicate a session is correctly routed.
func (l *Lister) SetProxyAddr(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.proxyAddr = addr
}

func (l *Lister) ProxyAddr() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.proxyAddr
}

// List discovers AI-tool sessions and classifies each.
func (l *Lister) List() ([]Session, error) {
	procs, err := scanProcesses()
	if err != nil {
		return nil, err
	}

	l.refreshHostIPs()

	out := make([]Session, 0, len(procs))
	for _, p := range procs {
		if p.PID == l.currentPID {
			continue
		}
		tool := classifyTool(p.Command)
		if tool == "" {
			continue
		}
		s := Session{
			PID:       p.PID,
			PPID:      p.PPID,
			User:      p.User,
			Command:   truncateCommand(p.Command, 240),
			Tool:      tool,
			StartedAt: p.StartedAt,
		}

		env, err := processEnv(p.PID)
		if err == nil {
			s.HasProxyEnv, s.ProxyEnv = detectProxyEnv(env)
			if env[BoundEnvKey] == BoundEnvValue {
				s.BoundFlag = true
			}
		}

		conns, _ := processConnections(p.PID)
		s.Connections = conns
		l.classifyConnections(&s)

		l.decide(&s)
		out = append(out, s)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Status != out[j].Status {
			// runaway first, then unknown, then protected
			rank := func(s Status) int {
				switch s {
				case StatusRunaway:
					return 0
				case StatusUnknown:
					return 1
				default:
					return 2
				}
			}
			return rank(out[i].Status) < rank(out[j].Status)
		}
		return out[i].StartedAt.After(out[j].StartedAt)
	})

	return out, nil
}

func (l *Lister) refreshHostIPs() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.hostIPsAt) < 60*time.Second && len(l.hostIPs) > 0 {
		return
	}
	fresh := make(map[string]bool)
	for _, h := range l.aiHosts {
		ips, err := lookupHost(h)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			fresh[ip] = true
		}
	}
	if len(fresh) > 0 {
		l.hostIPs = fresh
		l.hostIPsAt = time.Now()
	}
}

func (l *Lister) classifyConnections(s *Session) {
	l.mu.RLock()
	hostIPs := l.hostIPs
	proxyAddr := l.proxyAddr
	l.mu.RUnlock()

	proxyHost, proxyPort := splitHostPort(proxyAddr)
	for _, c := range s.Connections {
		host, port := splitHostPort(c)
		if host == "" {
			continue
		}
		if (host == "127.0.0.1" || host == "::1" || host == "localhost" || host == proxyHost) && port == proxyPort && proxyPort != "" {
			s.ViaProxy = true
			continue
		}
		if hostIPs[host] && (port == "443" || port == "80") {
			s.DirectAIConn = append(s.DirectAIConn, c)
		}
	}
}

func (l *Lister) decide(s *Session) {
	switch {
	case s.BoundFlag:
		s.Status = StatusProtected
		s.Reason = "tagged with REDACTR_BOUND=1"
	case s.HasProxyEnv && len(s.DirectAIConn) == 0:
		s.Status = StatusProtected
		s.Reason = "HTTPS_PROXY points at Redactr"
	case s.ViaProxy && len(s.DirectAIConn) == 0:
		s.Status = StatusProtected
		s.Reason = "TCP connection to Redactr proxy"
	case len(s.DirectAIConn) > 0:
		s.Status = StatusRunaway
		s.Reason = "direct connection to AI provider — bypassing the proxy"
	case s.HasProxyEnv && len(s.DirectAIConn) > 0:
		s.Status = StatusRunaway
		s.Reason = "proxy env set but traffic is going direct anyway"
	default:
		s.Status = StatusUnknown
		s.Reason = "no AI traffic observed yet"
	}
}

// classifyTool returns the friendly label for a known AI tool, or "" if the
// command does not match.
func classifyTool(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	first := cmdline
	if idx := strings.IndexByte(cmdline, ' '); idx > 0 {
		first = cmdline[:idx]
	}
	first = strings.ToLower(baseName(first))
	for _, t := range aiTools {
		if first == t.Match || strings.HasPrefix(first, t.Match) {
			return t.Label
		}
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func detectProxyEnv(env map[string]string) (bool, string) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v, ok := env[k]; ok && v != "" {
			return true, v
		}
	}
	return false, ""
}

func splitHostPort(addr string) (host, port string) {
	if addr == "" {
		return "", ""
	}
	// Strip any leading scheme (lsof gives raw host:port; never a URL)
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return strings.Trim(addr[:idx], "[]"), addr[idx+1:]
	}
	return addr, ""
}

func truncateCommand(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
