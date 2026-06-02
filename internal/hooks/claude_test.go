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
