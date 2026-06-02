package entropy

import (
	"math"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/redactrai/redactr/internal/scanner"
)

type entropyConfig struct {
	keywordGated  bool
	unconditional bool
}

type Scanner struct {
	threshold float64
	minLength int
	config    atomic.Pointer[entropyConfig]
}

func New(threshold float64, minLength int) *Scanner {
	s := &Scanner{
		threshold: threshold,
		minLength: minLength,
	}
	s.config.Store(&entropyConfig{
		keywordGated:  true,  // tier 1 default — fires only with keyword context
		unconditional: false, // tier 3 default — does not fire on bare high-entropy
	})
	return s
}

// SetEnabled controls which entropy-detection branches fire.
//
//	keywordGated  — entries whose entropy is in [threshold, 4.5) fire only
//	                when a secret-context keyword is within ±80 chars.
//	                Also gates entries ≥4.5 from firing without context
//	                when unconditional=false.
//	unconditional — entries ≥4.5 fire even without nearby keyword context.
func (s *Scanner) SetEnabled(keywordGated, unconditional bool) {
	s.config.Store(&entropyConfig{
		keywordGated:  keywordGated,
		unconditional: unconditional,
	})
}

func (s *Scanner) Name() string { return "entropy" }
func (s *Scanner) Ready() bool  { return true }

// Reconfigure conforms to scanner.Reconfigurable. It reads the two rule
// IDs that control entropy detection and forwards their states to
// SetEnabled.
func (s *Scanner) Reconfigure(enabled func(string) bool) {
	s.SetEnabled(enabled("entropy_keyword_gated"), enabled("entropy_unconditional"))
}

func (s *Scanner) Scan(text string) (*scanner.ScanResult, error) {
	start := time.Now()
	var findings []scanner.Finding
	cfg := s.config.Load()

	tokens := extractTokens(text, s.minLength)
	for _, tok := range tokens {
		if isLikelyNonSecret(tok.value) {
			continue
		}
		ent := shannonEntropy(tok.value)
		if ent < s.threshold {
			continue
		}
		hasContext := s.hasSecretContext(text, tok.start, tok.end)

		unconditionalFire := ent >= 4.5 && cfg.unconditional
		keywordFire := cfg.keywordGated && hasContext

		if !unconditionalFire && !keywordFire {
			continue
		}
		findings = append(findings, scanner.Finding{
			Label:      "ENTROPY-SECRET",
			Value:      tok.value,
			Start:      tok.start,
			End:        tok.end,
			Confidence: math.Min(ent/6.0, 1.0),
			Layer:      "entropy",
		})
	}

	return &scanner.ScanResult{
		Findings: findings,
		LayerMs:  time.Since(start).Milliseconds(),
	}, nil
}

type token struct {
	value string
	start int
	end   int
}

func extractTokens(text string, minLen int) []token {
	var tokens []token
	runes := []rune(text)
	i := 0
	for i < len(runes) {
		if isTokenChar(runes[i]) {
			j := i
			for j < len(runes) && isTokenChar(runes[j]) {
				j++
			}
			val := string(runes[i:j])
			if len(val) >= minLen && hasCharVariety(val) {
				tokens = append(tokens, token{value: val, start: i, end: j})
			}
			i = j
		} else {
			i++
		}
	}
	return tokens
}

func isTokenChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '/' || r == '=' || r == '-' || r == '_'
}

func hasCharVariety(s string) bool {
	classes := 0
	for _, r := range s {
		if unicode.IsUpper(r) {
			classes |= 1
		} else if unicode.IsLower(r) {
			classes |= 2
		} else if unicode.IsDigit(r) {
			classes |= 4
		} else {
			classes |= 8
		}
	}
	count := 0
	for classes > 0 {
		count += classes & 1
		classes >>= 1
	}
	return count >= 2
}

var secretContextWords = []string{
	"password", "passwd", "pwd", "secret", "token", "key", "api_key",
	"apikey", "credential", "private", "auth", "bearer", "access_key",
	"secret_key", "session", "cookie", "encrypt", "decrypt", "hash",
	"salt", "cipher", "signing", "hmac",
}

func (s *Scanner) hasSecretContext(text string, start, end int) bool {
	lower := strings.ToLower(text)
	windowStart := start - 80
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 80
	if windowEnd > len(lower) {
		windowEnd = len(lower)
	}
	window := lower[windowStart:windowEnd]
	for _, kw := range secretContextWords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func isLikelyNonSecret(s string) bool {
	lower := strings.ToLower(s)

	pathIndicators := []string{"org/", "com/", "xml", "schema", "xbrl", "spec/", "http", "www", "ftp"}
	for _, ind := range pathIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	if strings.Count(s, "/") >= 2 {
		return true
	}
	if strings.HasPrefix(s, "/") {
		return true
	}

	xCount := strings.Count(strings.ToUpper(s), "X")
	if xCount > 3 && float64(xCount)/float64(len(s)) > 0.2 {
		return true
	}

	parts := strings.Split(s, "-")
	if len(parts) >= 2 {
		allAlpha := true
		for _, p := range parts {
			for _, r := range p {
				if !unicode.IsLetter(r) {
					allAlpha = false
					break
				}
			}
			if !allAlpha {
				break
			}
		}
		if allAlpha {
			return true
		}
	}

	// CamelCase words are identifiers, not secrets
	if isCamelCase(s) {
		return true
	}

	// snake_case identifiers (2+ underscores or double underscore)
	if strings.Count(s, "_") >= 2 || strings.Contains(s, "__") {
		return true
	}

	// Tokens that are all uppercase letters (no digits/specials) are likely abbreviations or words
	allUpper := true
	for _, r := range s {
		if !unicode.IsUpper(r) {
			allUpper = false
			break
		}
	}
	if allUpper && len(s) < 20 {
		return true
	}

	// Tokens starting with REDACTED- are already redacted placeholders
	if strings.HasPrefix(s, "REDACTED-") {
		return true
	}

	return false
}

func isCamelCase(s string) bool {
	hasUpper := false
	hasLower := false
	hasNonAlpha := false
	for _, r := range s {
		if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsLower(r) {
			hasLower = true
		} else if !unicode.IsLetter(r) {
			hasNonAlpha = true
		}
	}
	return hasUpper && hasLower && !hasNonAlpha
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}
	length := float64(total)
	var ent float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}
