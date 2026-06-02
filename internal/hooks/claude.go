package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type ClaudeManager struct {
	settingsDir string
}

func NewClaudeManager(settingsDir string) *ClaudeManager {
	return &ClaudeManager{settingsDir: settingsDir}
}

func (m *ClaudeManager) InstallHook() error {
	settingsPath := filepath.Join(m.settingsDir, "settings.json")

	settings := make(map[string]interface{})
	if data, err := os.ReadFile(settingsPath); err == nil {
		json.Unmarshal(data, &settings)
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		hooks = make(map[string]interface{})
	}

	hooks["PreToolUse"] = []map[string]interface{}{
		{
			"matcher": "Bash",
			"hooks": []map[string]string{
				{
					"type":    "command",
					"command": "redactr-hook-check",
				},
			},
		},
	}

	settings["hooks"] = hooks

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsPath, data, 0644)
}

func (m *ClaudeManager) RemoveHook() error {
	settingsPath := filepath.Join(m.settingsDir, "settings.json")

	settings := make(map[string]interface{})
	if data, err := os.ReadFile(settingsPath); err == nil {
		json.Unmarshal(data, &settings)
	}

	if hooks, ok := settings["hooks"].(map[string]interface{}); ok {
		delete(hooks, "PreToolUse")
		if len(hooks) == 0 {
			delete(settings, "hooks")
		}
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsPath, data, 0644)
}
