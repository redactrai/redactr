// Package enrollment persists the desktop client's control-plane enrollment
// (server URL, device bearer token, and the server's public key) at
// ~/.redactr/enrollment.json.
package enrollment

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Enrollment struct {
	ServerURL       string `json:"server_url"`
	DeviceToken     string `json:"device_token"`
	ServerPublicKey string `json:"server_public_key"`
	DeviceID        string `json:"device_id"`
	OrgID           string `json:"org_id"`
}

func path(baseDir string) string { return filepath.Join(baseDir, "enrollment.json") }

func Exists(baseDir string) bool {
	_, err := os.Stat(path(baseDir))
	return err == nil
}

func Load(baseDir string) (Enrollment, error) {
	raw, err := os.ReadFile(path(baseDir))
	if err != nil {
		return Enrollment{}, err
	}
	var e Enrollment
	return e, json.Unmarshal(raw, &e)
}

func Save(baseDir string, e Enrollment) error {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp := path(baseDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path(baseDir))
}
