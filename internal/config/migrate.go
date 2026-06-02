package config

import (
	"os"

	"github.com/redactrai/redactr/internal/rules"
	"gopkg.in/yaml.v3"
)

// legacyScan captures the deprecated layer-flag fields directly from the
// YAML file. *bool is used so we can distinguish "absent" from "false".
type legacyScan struct {
	RegexEnabled   *bool `yaml:"regex_enabled"`
	EntropyEnabled *bool `yaml:"entropy_enabled"`
	GLiNEREnabled  *bool `yaml:"gliner_enabled"`
}

type legacyRoot struct {
	Scanning legacyScan `yaml:"scanning"`
}

// MigrateLegacyLayerFlagsFromFile reads the YAML at path and, if any of
// the deprecated layer flags are present and false, writes the
// corresponding rule entries (false) into c.Rules. Idempotent: relies
// on c.Migrated.
//
// Behaviour:
//   - If c.Migrated is true, returns immediately.
//   - If the file is missing or unreadable, marks Migrated and returns.
//   - For each legacy flag explicitly set to false in the file, every
//     rule whose Layer matches gets c.Rules[id] = false.
//   - Sets c.Migrated = true at end.
func MigrateLegacyLayerFlagsFromFile(c *ScanningConfig, path string) {
	if c.Migrated {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		c.Migrated = true
		return
	}
	var legacy legacyRoot
	if err := yaml.Unmarshal(data, &legacy); err != nil {
		c.Migrated = true
		return
	}
	if c.Rules == nil {
		c.Rules = make(map[string]bool)
	}
	apply := func(layer string, flag *bool) {
		if flag == nil || *flag {
			return
		}
		for _, r := range rules.AllRules() {
			if r.Layer == layer {
				c.Rules[r.ID] = false
			}
		}
	}
	apply("presidio", legacy.Scanning.RegexEnabled)
	apply("entropy", legacy.Scanning.EntropyEnabled)
	apply("gliner", legacy.Scanning.GLiNEREnabled)
	c.Migrated = true
}
