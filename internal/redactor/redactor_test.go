package redactor

import (
	"testing"

	"github.com/rakeshguha/redactr/internal/scanner"
)

func TestRedactSingleFinding(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "EMAIL", Value: "user@test.com", Start: 9, End: 22},
	}
	result := Redact("contact: user@test.com please", findings)
	expected := "contact: [REDACTED-EMAIL] please"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
	if len(result.Applied) != 1 {
		t.Errorf("expected 1 applied redaction, got %d", len(result.Applied))
	}
}

func TestRedactMultipleFindings(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "EMAIL", Value: "a@b.com", Start: 0, End: 7},
		{Label: "SSN", Value: "123-45-6789", Start: 12, End: 23},
	}
	result := Redact("a@b.com and 123-45-6789", findings)
	expected := "[REDACTED-EMAIL] and [REDACTED-SSN]"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
}

func TestRedactOverlappingFindings(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "SHORT", Value: "abc", Start: 0, End: 3},
		{Label: "LONG", Value: "abcdef", Start: 0, End: 6},
	}
	result := Redact("abcdef rest", findings)
	expected := "[REDACTED-LONG] rest"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
	if len(result.Applied) != 1 {
		t.Errorf("expected 1 applied (longest wins), got %d", len(result.Applied))
	}
}

func TestRedactNoFindings(t *testing.T) {
	result := Redact("clean text", nil)
	if result.Text != "clean text" {
		t.Errorf("expected unchanged text, got %q", result.Text)
	}
	if len(result.Applied) != 0 {
		t.Error("expected no applied redactions")
	}
}

func TestRedactCustomLabel(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "MY-PATTERN", Value: "PROJ-12345", Start: 5, End: 15},
	}
	result := Redact("ref: PROJ-12345 done", findings)
	expected := "ref: [REDACTED-MY-PATTERN] done"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
}

func TestRedactPreservesPositions(t *testing.T) {
	findings := []scanner.Finding{
		{Label: "A", Value: "xx", Start: 0, End: 2},
		{Label: "B", Value: "yy", Start: 5, End: 7},
	}
	result := Redact("xx + yy = zz", findings)
	expected := "[REDACTED-A] + [REDACTED-B] = zz"
	if result.Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Text)
	}
}
