package sidecar

import (
	"encoding/json"
	"fmt"
	"log/slog"
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

	slog.Info("sidecar starting", "event", "sidecar_starting", "layer", "gliner", "port", port)
	return nil
}

func (m *Manager) waitForReady() {
	for i := 0; i < 120; i++ {
		time.Sleep(1 * time.Second)
		if m.isHealthy() {
			slog.Info("sidecar ready", "event", "sidecar_ready", "layer", "gliner", "port", m.port)
			return
		}
	}
	slog.Error("sidecar timeout", "event", "sidecar_timeout", "layer", "gliner")
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
