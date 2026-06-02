package entropy

import (
	"math"
	"testing"
)

func TestHighEntropyStringDetected(t *testing.T) {
	s := New(4.0, 8)
	result, err := s.Scan("token = aB3xK9mZpQ2wR7nL")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least 1 finding for high-entropy string")
	}
	if result.Findings[0].Label != "ENTROPY-SECRET" {
		t.Errorf("expected label ENTROPY-SECRET, got %q", result.Findings[0].Label)
	}
}

func TestLowEntropyStringIgnored(t *testing.T) {
	s := New(4.0, 8)
	result, err := s.Scan("hello world this is normal text")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for low-entropy text, got %d", len(result.Findings))
	}
}

func TestRepeatedCharsIgnored(t *testing.T) {
	s := New(4.0, 8)
	result, err := s.Scan("aaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for repeated chars, got %d", len(result.Findings))
	}
}

func TestBase64StringDetected(t *testing.T) {
	s := New(3.5, 8)
	result, err := s.Scan("secret = aGVsbG8gd29ybGQhIQ==")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Label == "ENTROPY-SECRET" {
			found = true
		}
	}
	if !found {
		t.Error("expected base64 string to be detected as ENTROPY-SECRET")
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input  string
		minEnt float64
		maxEnt float64
	}{
		{"aaaa", 0, 0.01},
		{"ab", 0.99, 1.01},
		{"abcd", 1.99, 2.01},
		{"", 0, 0},
	}
	for _, tc := range tests {
		ent := shannonEntropy(tc.input)
		if ent < tc.minEnt || ent > tc.maxEnt {
			t.Errorf("shannonEntropy(%q) = %f, expected [%f, %f]", tc.input, ent, tc.minEnt, tc.maxEnt)
		}
	}
}

func TestCodeNotFlagged(t *testing.T) {
	s := New(4.5, 8)
	code := `func main() {
	fmt.Println("hello world")
	for i := 0; i < 10; i++ {
		fmt.Println(i)
	}
}`
	result, err := s.Scan(code)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for normal code, got %d", len(result.Findings))
	}
}

func TestCustomThreshold(t *testing.T) {
	low := New(2.0, 4)
	high := New(6.0, 4)
	input := "key=aB3xK9mZ"

	lowResult, _ := low.Scan(input)
	highResult, _ := high.Scan(input)

	if len(lowResult.Findings) == 0 {
		t.Error("low threshold should detect the token")
	}
	if len(highResult.Findings) != 0 {
		t.Error("high threshold should not detect the token")
	}
}

func TestLongRandomString(t *testing.T) {
	s := New(4.0, 8)
	s.SetEnabled(false /*keywordGated*/, true /*unconditional*/)
	long := "aB3xK9mZpQ2wR7nLyT5vU8cD1fG4hJ6"
	result, err := s.Scan(long)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Confidence < 0.5 || f.Confidence > 1.0 {
		t.Errorf("confidence %f out of expected range [0.5, 1.0]", f.Confidence)
	}
	_ = math.Min(0, 0)
}

func TestKeywordGatedOnly(t *testing.T) {
	s := New(4.5, 20)
	s.SetEnabled(true /*keywordGated*/, false /*unconditional*/)

	// High-entropy random token, no keyword nearby — should NOT fire.
	res, _ := s.Scan("the value is aB3xK9mZpQ2wR7nLyT5vU8cD1fG4hJ6sE0 in the changelog")
	if len(res.Findings) > 0 {
		t.Errorf("unconditional disabled — should not fire on bare high-entropy token; got %v", res.Findings)
	}

	// High-entropy with secret keyword — SHOULD fire.
	res2, _ := s.Scan("api_key = aB3xK9mZpQ2wR7nLyT5vU8cD1fG4hJ6sE0")
	if len(res2.Findings) == 0 {
		t.Error("keyword-gated should fire when secret keyword is nearby")
	}
}

func TestUnconditionalOnly(t *testing.T) {
	s := New(4.5, 20)
	s.SetEnabled(false /*keywordGated*/, true /*unconditional*/)

	// High-entropy bare token — SHOULD fire.
	res, _ := s.Scan("just a random value aB3xK9mZpQ2wR7nLyT5vU8cD1fG4hJ6sE0 here")
	if len(res.Findings) == 0 {
		t.Error("unconditional enabled — should fire on bare high-entropy token")
	}
}

func TestBothDisabled(t *testing.T) {
	s := New(4.5, 20)
	s.SetEnabled(false, false)
	res, _ := s.Scan("api_key = aB3xK9mZpQ2wR7nLyT5vU8cD1fG4hJ6sE0")
	if len(res.Findings) > 0 {
		t.Error("both disabled — entropy should fire on nothing")
	}
}

func TestDefaultsKeywordOnUnconditionalOff(t *testing.T) {
	// Without calling SetEnabled, the defaults should be: keywordGated=true, unconditional=false (Tier 1 vs Tier 3).
	s := New(4.5, 20)
	res, _ := s.Scan("just a random value aB3xK9mZpQ2wR7nLyT5vU8cD1fG4hJ6sE0 here")
	if len(res.Findings) > 0 {
		t.Errorf("default unconditional should be off; got %v", res.Findings)
	}
	res2, _ := s.Scan("api_key = aB3xK9mZpQ2wR7nLyT5vU8cD1fG4hJ6sE0")
	if len(res2.Findings) == 0 {
		t.Error("default keyword-gated should be on; expected a finding")
	}
}
