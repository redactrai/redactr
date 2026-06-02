package presidio

import (
	"testing"

	"github.com/rakeshguha/redactr/internal/scanner"
)

func hasFinding(findings []scanner.Finding, label string) bool {
	for _, f := range findings {
		if f.Label == label {
			return true
		}
	}
	return false
}

func TestCVVRequiresPaymentContext(t *testing.T) {
	s := New()

	cases := []struct {
		name string
		text string
		want bool
	}{
		{"with card context", "Visa ending 4242 cvv: 123 expires 04/27", true},
		{"with credit keyword", "credit card cvv: 999 stored", true},
		{"with cardholder context", "cardholder John Smith cvv 456", true},
		{"no context, build log", "the build cvv: 123 step failed", false},
		{"no context, prose", "she said cvv: 789 is the new acronym", false},
		{"with expiry keyword", "expires 12/29 cvv 111", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.Scan(tc.text)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got := hasFinding(res.Findings, "CVV")
			if got != tc.want {
				t.Errorf("CVV match: got=%v want=%v\nfindings: %+v", got, tc.want, res.Findings)
			}
		})
	}
}

func TestPresidioRespectsEnabled(t *testing.T) {
	enabled := map[string]bool{
		"aws_access_key": false,
		"email_regex":    true,
		"jwt":            false,
	}
	pred := func(id string) bool {
		v, ok := enabled[id]
		return ok && v
	}
	s := NewWithEnabled(pred)

	res, err := s.Scan("AWS key AKIAIOSFODNN7EXAMPLE and email a@b.com plus jwt eyJabc.eyJdef.ghi")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings {
		if f.Label == "AWS_ACCESS_KEY" {
			t.Errorf("aws_access_key should be disabled, but found %+v", f)
		}
		if f.Label == "JWT" {
			t.Errorf("jwt should be disabled, but found %+v", f)
		}
	}
	if !hasFinding(res.Findings, "EMAIL_ADDRESS") {
		t.Error("email_regex was enabled — expected EMAIL_ADDRESS finding")
	}
}

func TestPresidioReconfigure(t *testing.T) {
	allOn := func(string) bool { return true }
	allOff := func(string) bool { return false }

	s := NewWithEnabled(allOn)
	res, _ := s.Scan("AKIAIOSFODNN7EXAMPLE")
	if !hasFinding(res.Findings, "AWS_ACCESS_KEY") {
		t.Fatal("setup: AWS_ACCESS_KEY should match when all rules enabled")
	}

	s.Reconfigure(allOff)
	res2, _ := s.Scan("AKIAIOSFODNN7EXAMPLE")
	if hasFinding(res2.Findings, "AWS_ACCESS_KEY") {
		t.Error("after Reconfigure(allOff), AWS_ACCESS_KEY should not match")
	}

	s.Reconfigure(allOn)
	res3, _ := s.Scan("AKIAIOSFODNN7EXAMPLE")
	if !hasFinding(res3.Findings, "AWS_ACCESS_KEY") {
		t.Error("after Reconfigure(allOn), AWS_ACCESS_KEY should match again")
	}
}

func TestPresidioNewIsBackwardCompatible(t *testing.T) {
	// New() with no predicate should match everything.
	s := New()
	res, _ := s.Scan("AKIAIOSFODNN7EXAMPLE and a@b.com")
	if !hasFinding(res.Findings, "AWS_ACCESS_KEY") {
		t.Error("legacy New() should still match AWS_ACCESS_KEY")
	}
	if !hasFinding(res.Findings, "EMAIL_ADDRESS") {
		t.Error("legacy New() should still match EMAIL_ADDRESS")
	}
}
