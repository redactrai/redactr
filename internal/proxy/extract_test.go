package proxy

import (
	"testing"
)

func TestExtractAnthropicLastMessage(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": "first message"},
			{"role": "assistant", "content": "response"},
			{"role": "user", "content": "contact me at user@secret.com"}
		]
	}`

	msg, err := ExtractLastUserMessage([]byte(body), "api.anthropic.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Text != "contact me at user@secret.com" {
		t.Errorf("expected last user message, got %q", msg.Text)
	}
	if msg.Index != 2 {
		t.Errorf("expected index 2, got %d", msg.Index)
	}
}

func TestExtractOpenAILastMessage(t *testing.T) {
	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "you are helpful"},
			{"role": "user", "content": "first"},
			{"role": "assistant", "content": "sure"},
			{"role": "user", "content": "my SSN is 123-45-6789"}
		]
	}`

	msg, err := ExtractLastUserMessage([]byte(body), "api.openai.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Text != "my SSN is 123-45-6789" {
		t.Errorf("expected last user message, got %q", msg.Text)
	}
}

func TestExtractWithContentArray(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": [
				{"type": "text", "text": "here is my key: AKIAIOSFODNN7EXAMPLE"},
				{"type": "text", "text": "and email user@test.com"}
			]}
		]
	}`

	msg, err := ExtractLastUserMessage([]byte(body), "api.anthropic.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Text != "here is my key: AKIAIOSFODNN7EXAMPLE\nand email user@test.com" {
		t.Errorf("unexpected extracted text: %q", msg.Text)
	}
	if len(msg.ContentParts) != 2 {
		t.Errorf("expected 2 content parts, got %d", len(msg.ContentParts))
	}
}

func TestExtractToolResult(t *testing.T) {
	body := `{
		"model": "claude-sonnet-4-20250514",
		"messages": [
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "123", "content": "file contents: API_KEY=sk-secret123"}
			]}
		]
	}`

	msg, err := ExtractLastUserMessage([]byte(body), "api.anthropic.com")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if msg.Text != "file contents: API_KEY=sk-secret123" {
		t.Errorf("expected tool result text, got %q", msg.Text)
	}
}

func TestExtractNoMessages(t *testing.T) {
	body := `{"model": "gpt-4", "messages": []}`
	_, err := ExtractLastUserMessage([]byte(body), "api.openai.com")
	if err == nil {
		t.Error("expected error for empty messages")
	}
}
