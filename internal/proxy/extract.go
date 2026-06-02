package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ExtractedMessage struct {
	Text         string
	Index        int
	ContentParts []ContentPart
	IsArray      bool
}

type ContentPart struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	Content   string `json:"content,omitempty"`
	ToolUseID string `json:"tool_use_id,omitempty"`
}

type apiRequest struct {
	Messages []apiMessage `json:"messages"`
}

type apiMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func ExtractLastUserMessage(body []byte, host string) (*ExtractedMessage, error) {
	var req apiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse request body: %w", err)
	}

	for i := len(req.Messages) - 1; i >= 0; i-- {
		msg := req.Messages[i]
		if msg.Role != "user" {
			continue
		}

		var strContent string
		if err := json.Unmarshal(msg.Content, &strContent); err == nil {
			return &ExtractedMessage{Text: strContent, Index: i}, nil
		}

		var parts []ContentPart
		if err := json.Unmarshal(msg.Content, &parts); err == nil {
			var texts []string
			for _, p := range parts {
				switch p.Type {
				case "text":
					texts = append(texts, p.Text)
				case "tool_result":
					if p.Content != "" {
						texts = append(texts, p.Content)
					}
				}
			}
			return &ExtractedMessage{
				Text:         strings.Join(texts, "\n"),
				Index:        i,
				ContentParts: parts,
				IsArray:      true,
			}, nil
		}

		return nil, fmt.Errorf("unsupported content format at message %d", i)
	}

	return nil, fmt.Errorf("no user message found")
}

func ReplaceLastUserMessage(body []byte, msg *ExtractedMessage, redactedText string) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(raw["messages"], &messages); err != nil {
		return nil, err
	}

	if msg.IsArray {
		redactedParts := make([]ContentPart, len(msg.ContentParts))
		texts := strings.Split(redactedText, "\n")
		textIdx := 0
		for i, p := range msg.ContentParts {
			redactedParts[i] = p
			switch p.Type {
			case "text":
				if textIdx < len(texts) {
					redactedParts[i].Text = texts[textIdx]
					textIdx++
				}
			case "tool_result":
				if textIdx < len(texts) {
					redactedParts[i].Content = texts[textIdx]
					textIdx++
				}
			}
		}
		partBytes, err := json.Marshal(redactedParts)
		if err != nil {
			return nil, err
		}
		msgObj := map[string]json.RawMessage{
			"role":    json.RawMessage(`"user"`),
			"content": partBytes,
		}
		msgBytes, err := json.Marshal(msgObj)
		if err != nil {
			return nil, err
		}
		messages[msg.Index] = msgBytes
	} else {
		contentBytes, err := json.Marshal(redactedText)
		if err != nil {
			return nil, err
		}
		msgObj := map[string]json.RawMessage{
			"role":    json.RawMessage(`"user"`),
			"content": contentBytes,
		}
		msgBytes, err := json.Marshal(msgObj)
		if err != nil {
			return nil, err
		}
		messages[msg.Index] = msgBytes
	}

	msgBytes, err := json.Marshal(messages)
	if err != nil {
		return nil, err
	}
	raw["messages"] = msgBytes

	return json.Marshal(raw)
}
