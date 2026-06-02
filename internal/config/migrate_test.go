package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeYAML(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestMigrateAllOnNoChanges(t *testing.T) {
	path := writeYAML(t, "scanning:\n  regex_enabled: true\n  entropy_enabled: true\n  gliner_enabled: true\n")
	c := &ScanningConfig{}
	MigrateLegacyLayerFlagsFromFile(c, path)
	if !c.Migrated {
		t.Error("Migrated should be set after migration")
	}
	if len(c.Rules) != 0 {
		t.Errorf("all-on legacy config should leave Rules empty; got %d entries", len(c.Rules))
	}
}

func TestMigrateRegexOff(t *testing.T) {
	path := writeYAML(t, "scanning:\n  regex_enabled: false\n  entropy_enabled: true\n  gliner_enabled: true\n")
	c := &ScanningConfig{}
	MigrateLegacyLayerFlagsFromFile(c, path)
	if v, ok := c.Rules["aws_access_key"]; !ok || v {
		t.Errorf("aws_access_key (presidio, tier 1) should be false; got ok=%v v=%v", ok, v)
	}
	if v, ok := c.Rules["email_regex"]; !ok || v {
		t.Errorf("email_regex (presidio, tier 2) should be false; got ok=%v v=%v", ok, v)
	}
	if _, ok := c.Rules["person_gliner"]; ok {
		t.Error("person_gliner should not be in Rules when its layer is on")
	}
}

func TestMigrateEntropyOff(t *testing.T) {
	path := writeYAML(t, "scanning:\n  regex_enabled: true\n  entropy_enabled: false\n  gliner_enabled: true\n")
	c := &ScanningConfig{}
	MigrateLegacyLayerFlagsFromFile(c, path)
	if v, ok := c.Rules["entropy_keyword_gated"]; !ok || v {
		t.Errorf("entropy_keyword_gated should be false; got ok=%v v=%v", ok, v)
	}
	if v, ok := c.Rules["entropy_unconditional"]; !ok || v {
		t.Errorf("entropy_unconditional should be false; got ok=%v v=%v", ok, v)
	}
}

func TestMigrateGLiNEROff(t *testing.T) {
	path := writeYAML(t, "scanning:\n  regex_enabled: true\n  entropy_enabled: true\n  gliner_enabled: false\n")
	c := &ScanningConfig{}
	MigrateLegacyLayerFlagsFromFile(c, path)
	if v, ok := c.Rules["person_gliner"]; !ok || v {
		t.Errorf("person_gliner should be false; got ok=%v v=%v", ok, v)
	}
}

func TestMigrateRunsOnce(t *testing.T) {
	path := writeYAML(t, "scanning:\n  regex_enabled: false\n")
	c := &ScanningConfig{Migrated: true}
	MigrateLegacyLayerFlagsFromFile(c, path)
	if len(c.Rules) != 0 {
		t.Error("migration must be idempotent when Migrated=true")
	}
}

func TestMigrateMissingFile(t *testing.T) {
	c := &ScanningConfig{}
	MigrateLegacyLayerFlagsFromFile(c, "/nonexistent/path/config.yaml")
	if !c.Migrated {
		t.Error("Migrated should be set even when file is missing")
	}
	if len(c.Rules) != 0 {
		t.Errorf("missing file should not write any rules; got %d entries", len(c.Rules))
	}
}
