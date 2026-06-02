package regex

import (
	"testing"
)

func TestDetectEmail(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, err := s.Scan("contact me at user@example.com for details")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "EMAIL" {
		t.Errorf("expected label EMAIL, got %q", result.Findings[0].Label)
	}
	if result.Findings[0].Value != "user@example.com" {
		t.Errorf("expected value 'user@example.com', got %q", result.Findings[0].Value)
	}
}

func TestDetectSSN(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("SSN is 123-45-6789")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "SSN" {
		t.Errorf("expected SSN, got %q", result.Findings[0].Label)
	}
}

func TestDetectAWSKey(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("aws_key = AKIAIOSFODNN7EXAMPLE")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "AWS-ACCESS-KEY" {
		t.Errorf("expected AWS-ACCESS-KEY, got %q", result.Findings[0].Label)
	}
}

func TestDetectCreditCard(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("card: 4111-1111-1111-1111")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "CREDIT-CARD" {
		t.Errorf("expected CREDIT-CARD, got %q", result.Findings[0].Label)
	}
}

func TestDetectPhoneNumber(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("call me at (555) 123-4567")
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "PHONE" {
		t.Errorf("expected PHONE, got %q", result.Findings[0].Label)
	}
}

func TestDetectPrivateKey(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	input := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	result, _ := s.Scan(input)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Label != "PRIVATE-KEY" {
		t.Errorf("expected PRIVATE-KEY, got %q", result.Findings[0].Label)
	}
}

func TestDetectJWT(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	found := false
	for _, f := range result.Findings {
		if f.Label == "JWT" {
			found = true
		}
	}
	if !found {
		t.Error("expected JWT to be detected")
	}
}

func TestCustomPatterns(t *testing.T) {
	custom := []PatternDef{
		{Name: "INTERNAL-ID", Pattern: `PROJ-\d{4,6}`},
	}
	s := New(DefaultPatterns(), custom)
	result, _ := s.Scan("ticket PROJ-12345 is critical")
	found := false
	for _, f := range result.Findings {
		if f.Label == "INTERNAL-ID" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom pattern INTERNAL-ID to match")
	}
}

func TestNoFalsePositives(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("func main() { fmt.Println(\"hello world\") }")
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings on clean code, got %d", len(result.Findings))
	}
}

func TestMultipleFindings(t *testing.T) {
	s := New(DefaultPatterns(), nil)
	result, _ := s.Scan("email user@test.com and SSN 123-45-6789")
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}
