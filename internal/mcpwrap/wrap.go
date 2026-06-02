package mcpwrap

import (
	"encoding/json"
	"strings"
)

type RemoteScanner interface {
	ScanText(text string) (string, error)
}

func ScanMessage(msg []byte, scanner RemoteScanner) ([]byte, error) {
	if scanner == nil {
		return msg, nil
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(msg, &parsed); err != nil {
		return msg, nil
	}

	text := extractTextFromMessage(parsed)
	if text == "" {
		return msg, nil
	}

	redacted, err := scanner.ScanText(text)
	if err != nil {
		return msg, nil
	}

	if redacted == text {
		return msg, nil
	}

	result := strings.Replace(string(msg), text, redacted, 1)
	return []byte(result), nil
}

func extractTextFromMessage(msg map[string]json.RawMessage) string {
	if result, ok := msg["result"]; ok {
		var resultObj map[string]json.RawMessage
		if err := json.Unmarshal(result, &resultObj); err == nil {
			if content, ok := resultObj["content"]; ok {
				var parts []map[string]interface{}
				if err := json.Unmarshal(content, &parts); err == nil {
					var texts []string
					for _, p := range parts {
						if t, ok := p["text"].(string); ok {
							texts = append(texts, t)
						}
					}
					return strings.Join(texts, "\n")
				}
			}
		}

		var resultStr string
		if err := json.Unmarshal(result, &resultStr); err == nil {
			return resultStr
		}
	}

	if params, ok := msg["params"]; ok {
		var paramsObj map[string]json.RawMessage
		if err := json.Unmarshal(params, &paramsObj); err == nil {
			if content, ok := paramsObj["content"]; ok {
				var contentStr string
				if err := json.Unmarshal(content, &contentStr); err == nil {
					return contentStr
				}
			}
		}
	}

	return ""
}
