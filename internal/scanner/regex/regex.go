package regex

import (
	"regexp"
	"time"

	"github.com/rakeshguha/redactr/internal/scanner"
)

type PatternDef struct {
	Name    string `json:"name" yaml:"name"`
	Pattern string `json:"pattern" yaml:"pattern"`
}

type Scanner struct {
	patterns []compiledPattern
}

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

func DefaultPatterns() []PatternDef {
	return []PatternDef{
		{Name: "EMAIL", Pattern: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`},

		// SSN: require separators (dashes or spaces) — bare 9-digit numbers cause massive FPs
		{Name: "SSN", Pattern: `\b\d{3}-\d{2}-\d{4}\b`},
		{Name: "SSN", Pattern: `\b\d{3}\s\d{2}\s\d{4}\b`},

		{Name: "CREDIT-CARD", Pattern: `\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b`},

		// Phone: require parens, separators, or + prefix — bare digit runs match financial refs
		{Name: "PHONE", Pattern: `\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}`},
		{Name: "PHONE", Pattern: `\b\d{3}[\-\.]\d{3}[\-\.]\d{4}\b`},
		{Name: "PHONE", Pattern: `\+\d{1,4}[\s\-.]?\(?\d{1,5}\)?[\s\-.]?\d{2,5}[\s\-.]?\d{2,5}[\s\-.]?\d{0,5}`},
		{Name: "PHONE", Pattern: `\b0\d{2,4}[\s.\-]\d{3,8}[\s.\-]?\d{0,6}\b`},
		{Name: "PHONE", Pattern: `\b00\d{2,4}[\s.\-]\d{2,5}[\s\-.]?\d{3,5}[\s\-.]?\d{0,5}\b`},

		{Name: "AWS-ACCESS-KEY", Pattern: `AKIA[0-9A-Z]{16}`},
		{Name: "AWS-SECRET-KEY", Pattern: `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`},
		{Name: "GCP-API-KEY", Pattern: `AIza[0-9A-Za-z\-_]{35}`},
		{Name: "PRIVATE-KEY", Pattern: `(?s)-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`},
		{Name: "JWT", Pattern: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]+`},
		{Name: "CONNECTION-STRING", Pattern: `(?i)(mongodb|postgres|mysql|redis|amqp):\/\/[^\s]+`},
		{Name: "GENERIC-SECRET", Pattern: `(?i)(password|secret|token|api_key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9/+=\-_]{8,}['"]?`},
		{Name: "GENERIC-SECRET", Pattern: `(?i)(password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{4,}['"]?`},
		{Name: "IP-ADDRESS", Pattern: `\b(?:\d{1,3}\.){3}\d{1,3}\b`},
		// IPv6: full form only (8 groups) — shortened forms match random hex
		{Name: "IPV6-ADDRESS", Pattern: `\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}\b`},
		{Name: "IPV6-ADDRESS", Pattern: `\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7}::[0-9a-fA-F:]*\b`},

		// Passport: require keyword context to avoid matching format codes
		{Name: "PASSPORT", Pattern: `(?i)(?:passport|travel\s+doc(?:ument)?)\s*(?:no|number|#|:)\s*[A-Z]{0,2}\d{6,9}\b`},

		// Driver license: require keyword context — bare alpha+digit combos match currency amounts
		{Name: "DRIVER-LICENSE", Pattern: `(?i)(?:driver'?s?\s*(?:license|licence|lic)|DL|DMV)\s*(?:no|number|#|:)\s*[A-Z0-9][\-.]?[A-Z0-9]{5,12}\b`},

		// --- EU Financial Patterns ---
		// IBAN: 2 letter country code + 2 check digits + up to 30 alphanumeric (covers all EU countries)
		{Name: "IBAN", Pattern: `\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b`},

		// MAC address (colon, dash, or space separated)
		{Name: "MAC-ADDRESS", Pattern: `\b[0-9a-fA-F]{2}[:\-\s][0-9a-fA-F]{2}[:\-\s][0-9a-fA-F]{2}[:\-\s][0-9a-fA-F]{2}[:\-\s][0-9a-fA-F]{2}[:\-\s][0-9a-fA-F]{2}\b`},

		// IMEI: 15 digits with optional dash separators
		{Name: "IMEI", Pattern: `\b\d{2}-\d{6}-\d{6}-\d{1}\b`},

		// Credit card without separators: 13-19 digits (Visa starts 4, MC starts 5, Amex 34/37)
		{Name: "CREDIT-CARD", Pattern: `\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b`},

		// Password: require non-common-word value after keyword
		{Name: "PASSWORD", Pattern: `(?i)(?:password|passwd|pwd|passcode)\s*(?:is|was|:)\s*(?!(?:valid|invalid|temporary|required|optional|incorrect|correct|wrong|right|expired|changed|reset|secure|strong|weak|empty|null|blank|missing|set|enabled|disabled|locked|unlocked)\b)[^\s,;]{4,40}`},

		// Credit card expiration dates
		{Name: "CC-EXPIRY", Pattern: `\b(?:0[1-9]|1[0-2])\/(?:2[0-9]|3[0-9])\b`},

		// URL patterns — catch full http(s) URLs, exclude XML namespace URIs
		{Name: "URL", Pattern: `https?://(?!(?:www\.)?(?:w3\.org|xbrl\.org|fpml\.org|xmlsoap\.org|schemas\.xmlsoap\.org|xml\.org))[^\s<>"')\]]+`},

		// US bank routing / account numbers with keyword context
		{Name: "BANK-ACCOUNT", Pattern: `(?i)(?:account|acct|routing)\s*(?:no|number|num|#|:)\s*[A-Z]{0,4}\d{6,18}\b`},

		// Insurance/health plan numbers with keyword context
		{Name: "INSURANCE-ID", Pattern: `(?i)(?:insurance|policy|health\s*plan|member)\s*(?:no|number|id|#|:)\s*[A-Z]{0,3}\d{6,12}\b`},

		// Student/registration IDs with keyword context — require at least one digit in the value
		{Name: "REGISTRATION-ID", Pattern: `(?i)(?:student|registration|reg|enrollment)\s*(?:no|number|id|#|:)\s*(?=[A-Z0-9\-]*\d)[A-Z0-9\-]{5,15}\b`},
	}
}

func New(defaults []PatternDef, custom []PatternDef) *Scanner {
	all := append(defaults, custom...)
	var compiled []compiledPattern
	for _, p := range all {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledPattern{name: p.Name, re: re})
	}
	return &Scanner{patterns: compiled}
}

func (s *Scanner) Name() string { return "regex" }
func (s *Scanner) Ready() bool  { return true }

func (s *Scanner) Scan(text string) (*scanner.ScanResult, error) {
	start := time.Now()
	var findings []scanner.Finding

	for _, p := range s.patterns {
		matches := p.re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			findings = append(findings, scanner.Finding{
				Label:      p.name,
				Value:      text[m[0]:m[1]],
				Start:      m[0],
				End:        m[1],
				Confidence: 1.0,
				Layer:      "regex",
			})
		}
	}

	return &scanner.ScanResult{
		Findings: findings,
		LayerMs:  time.Since(start).Milliseconds(),
	}, nil
}
