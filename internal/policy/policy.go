// Package policy holds the locally-cached launch policy. Until subsystem A
// ships, it is seeded from config and persisted at ~/.redactr/cache/policy.json.
package policy

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Policy is the persisted launch policy (no live runtime fields).
type Policy struct {
	Image     string    `json:"image"`
	MountMode string    `json:"mountMode"` // "bind" | "diffback"
	Denylist  []string  `json:"denylist"`
	Version   int       `json:"version"`
	FetchedAt time.Time `json:"fetchedAt"`
}

// Seed returns the default policy used when no cache exists and no server has
// been contacted. denylist comes from config (cfg.Proxy.BlockedDomains).
func Seed(denylist []string) Policy {
	return Policy{Image: "redactr-base:local", MountMode: "bind", Denylist: denylist}
}

func cachePath(baseDir string) string {
	return filepath.Join(baseDir, "cache", "policy.json")
}

// Load reads the cached policy; if the file is absent it returns Seed(denylist).
// SEAM: subsystem A will refresh the persisted policy from the signed server bundle.
func Load(baseDir string, denylist []string) (Policy, error) {
	raw, err := os.ReadFile(cachePath(baseDir))
	if errors.Is(err, fs.ErrNotExist) {
		return Seed(denylist), nil
	}
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Save atomically writes the policy to the cache (temp file + rename).
func Save(baseDir string, p Policy) error {
	dir := filepath.Join(baseDir, "cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "policy.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, cachePath(baseDir))
}
