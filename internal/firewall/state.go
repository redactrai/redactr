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
