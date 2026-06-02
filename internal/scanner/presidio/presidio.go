// Package presidio implements PII detection patterns ported from Microsoft's
// Presidio open-source library (MIT license).
// Source: https://github.com/microsoft/presidio
package presidio

import (
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/rakeshguha/redactr/internal/scanner"
)

type patternDef struct {
	label      string
	ruleID     string
	re         *regexp.Regexp
	score      float64
	context    []string
	validate   func(string) bool
	contextReq bool
}

type presidioState struct {
	patterns []patternDef
	enabled  func(string) bool
}

type Scanner struct {
	state atomic.Pointer[presidioState]
}

// New returns a Presidio scanner with all rules enabled.
func New() *Scanner {
	return NewWithEnabled(func(string) bool { return true })
}

// NewWithEnabled returns a Presidio scanner that only registers patterns
// whose rule ID is enabled by the predicate. Patterns without a ruleID
// are always enabled (defensive default for partially-mapped rules).
func NewWithEnabled(enabled func(ruleID string) bool) *Scanner {
	s := &Scanner{}
	s.rebuild(enabled)
	return s
}

// Reconfigure atomically replaces the scanner's compiled pattern set.
// Concurrent calls to Scan see either the old or the new state — never
// a torn read.
func (s *Scanner) Reconfigure(enabled func(string) bool) {
	s.rebuild(enabled)
}

// rebuild compiles a fresh pattern slice for the given predicate and
// installs it via an atomic store.
func (s *Scanner) rebuild(enabled func(string) bool) {
	patterns := compilePatterns(enabled)
	s.state.Store(&presidioState{
		patterns: patterns,
		enabled:  enabled,
	})
}

func (s *Scanner) Name() string { return "presidio" }
func (s *Scanner) Ready() bool  { return true }

func (s *Scanner) Scan(text string) (*scanner.ScanResult, error) {
	start := time.Now()
	var findings []scanner.Finding
	lower := strings.ToLower(text)
	state := s.state.Load()
	if state == nil {
		// Defensive: no state installed yet (shouldn't happen via constructors).
		return &scanner.ScanResult{LayerMs: time.Since(start).Milliseconds()}, nil
	}

	for _, p := range state.patterns {
		matches := p.re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			matched := text[m[0]:m[1]]

			if p.validate != nil && !p.validate(matched) {
				continue
			}

			score := p.score
			if len(p.context) > 0 {
				windowStart := m[0] - 100
				if windowStart < 0 {
					windowStart = 0
				}
				windowEnd := m[1] + 100
				if windowEnd > len(lower) {
					windowEnd = len(lower)
				}
				window := lower[windowStart:windowEnd]
				boost := false
				for _, ctx := range p.context {
					if strings.Contains(window, ctx) {
						boost = true
						break
					}
				}
				if boost {
					score += 0.35
					if score > 1.0 {
						score = 1.0
					}
				} else if p.contextReq {
					continue
				}
			}

			if score < 0.3 {
				continue
			}

			findings = append(findings, scanner.Finding{
				Label:      p.label,
				Value:      matched,
				Start:      m[0],
				End:        m[1],
				Confidence: score,
				Layer:      "presidio",
			})
		}
	}

	return &scanner.ScanResult{
		Findings: findings,
		LayerMs:  time.Since(start).Milliseconds(),
	}, nil
}

func compilePatterns(enabled func(string) bool) []patternDef {
	type raw struct {
		label      string
		ruleID     string
		pattern    string
		score      float64
		context    []string
		validate   func(string) bool
		contextReq bool
	}

	defs := []raw{
		// =====================================================================
		// CREDIT CARD — from credit_card_recognizer.py
		// =====================================================================
		{
			label:   "CREDIT_CARD",
			ruleID:  "credit_card_luhn",
			pattern: `\b(?!1\d{12}(?!\d))((4\d{3})|(5[0-5]\d{2})|(6\d{3})|(1\d{3})|(3\d{3}))[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b`,
			score:   0.3,
			context: []string{"credit", "card", "visa", "mastercard", "cc", "amex", "discover", "jcb", "diners", "maestro"},
			validate: func(s string) bool {
				digits := stripNonDigits(s)
				if len(digits) < 12 || len(digits) > 19 {
					return false
				}
				return luhn(digits)
			},
		},

		// =====================================================================
		// CRYPTO — from crypto_recognizer.py
		// =====================================================================
		{
			label:   "CRYPTO",
			ruleID:  "crypto_btc",
			pattern: `\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}\b`,
			score:   0.5,
			context: []string{"wallet", "btc", "bitcoin", "crypto"},
		},
		{
			label:   "CRYPTO",
			ruleID:  "crypto_eth",
			pattern: `\b0x[a-fA-F0-9]{40}\b`,
			score:   0.5,
			context: []string{"wallet", "eth", "ethereum", "crypto"},
		},

		// =====================================================================
		// EMAIL — from email_recognizer.py
		// =====================================================================
		{
			label:   "EMAIL_ADDRESS",
			ruleID:  "email_regex",
			pattern: `\b((([!#$%&'*+\-/=?^_` + "`" + `{|}~\w])|([!#$%&'*+\-/=?^_` + "`" + `{|}~\w][!#$%&'*+\-/=?^_` + "`" + `{|}~.\w]{0,}[!#$%&'*+\-/=?^_` + "`" + `{|}~\w]))[@]\w+([-.]\w+)*\.\w+([-.]\w+)*)\b`,
			score:   0.5,
			context: []string{"email"},
		},

		// =====================================================================
		// IBAN — from iban_recognizer.py
		// =====================================================================
		{
			label:   "IBAN_CODE",
			ruleID:  "iban_presidio",
			pattern: `(?:[^A-Z0-9]|^)([A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?)(?:[^A-Z0-9]|$)`,
			score:   0.5,
			context: []string{"iban", "bank", "transaction", "account"},
			validate: func(s string) bool {
				clean := strings.Map(func(r rune) rune {
					if r == ' ' || r == '-' {
						return -1
					}
					return r
				}, strings.TrimSpace(s))
				if len(clean) < 15 || len(clean) > 34 {
					return false
				}
				return ibanCheckDigit(clean)
			},
		},

		// =====================================================================
		// IP ADDRESS — from ip_recognizer.py
		// =====================================================================
		{
			label:   "IP_ADDRESS",
			ruleID:  "ipv4",
			pattern: `\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-2]?\d|3[0-2]))?\b`,
			score:   0.6,
			context: []string{"ip", "ipv4", "ipv6", "address"},
		},
		{
			label:   "IP_ADDRESS",
			ruleID:  "ipv6",
			pattern: `(?:[^:\w])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|:(?::[0-9A-Fa-f]{1,4}){1,7}|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?::[0-9A-Fa-f]{1,4}){1,6})(?:[^:\w]|$)`,
			score:   0.6,
			context: []string{"ip", "ipv4", "ipv6"},
		},

		// =====================================================================
		// URL — catch all URLs, filter out XML namespaces and schema URLs
		// =====================================================================
		{
			label:   "URL",
			ruleID:  "url_bare",
			pattern: `https?://[^\s<>"')\]]+`,
			score:   0.5,
			validate: func(s string) bool {
				lower := strings.ToLower(s)
				nonPII := []string{"w3.org", "xml", "schema", "xmlns", "xsd", "dtd",
					"xbrl", "spec/", "json-schema", "openid", "oauth",
					"example.com", "example.org", "localhost",
					"fpml.org", "iso.org", "ietf.org", "oasis-open.org"}
				for _, np := range nonPII {
					if strings.Contains(lower, np) {
						return false
					}
				}
				return true
			},
		},

		// =====================================================================
		// DATE_TIME — only fire on DOB context (standalone dates are Tier 3)
		// =====================================================================
		{
			label:      "DATE_OF_BIRTH",
			ruleID:     "dob_mdy",
			pattern:    `\b(?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])[/\-.](?:\d{4}|\d{2})\b`,
			score:      0.3,
			context:    []string{"birthday", "born", "dob", "date of birth", "birth date", "birthdate"},
			contextReq: true,
		},
		{
			label:      "DATE_OF_BIRTH",
			ruleID:     "dob_dmy",
			pattern:    `\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:\d{4}|\d{2})\b`,
			score:      0.3,
			context:    []string{"birthday", "born", "dob", "date of birth", "birth date", "birthdate"},
			contextReq: true,
		},

		// =====================================================================
		// MAC ADDRESS — from mac_recognizer.py
		// =====================================================================
		{
			label:   "MAC_ADDRESS",
			ruleID:  "mac_colon_dash",
			pattern: `\b[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\b`,
			score:   0.6,
			context: []string{"mac", "mac address", "hardware address", "physical address", "ethernet", "device"},
			validate: func(s string) bool {
				clean := strings.Map(func(r rune) rune {
					if r == ':' {
						return -1
					}
					return unicode.ToUpper(r)
				}, s)
				return clean != "000000000000" && clean != "FFFFFFFFFFFF"
			},
		},
		{
			label:   "MAC_ADDRESS",
			ruleID:  "mac_colon_dash",
			pattern: `\b[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}\b`,
			score:   0.6,
			context: []string{"mac", "mac address", "hardware address", "physical address", "ethernet", "device"},
			validate: func(s string) bool {
				clean := strings.Map(func(r rune) rune {
					if r == '-' {
						return -1
					}
					return unicode.ToUpper(r)
				}, s)
				return clean != "000000000000" && clean != "FFFFFFFFFFFF"
			},
		},
		{
			label:   "MAC_ADDRESS",
			ruleID:  "mac_cisco_dot",
			pattern: `\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b`,
			score:   0.6,
			context: []string{"mac", "mac address", "hardware address", "cisco"},
		},

		// =====================================================================
		// US SSN — from us_ssn_recognizer.py
		// =====================================================================
		{
			label:   "US_SSN",
			ruleID:  "us_ssn_dash",
			pattern: `\b([0-9]{3})[- .]([0-9]{2})[- .]([0-9]{4})\b`,
			score:   0.5,
			context: []string{"social", "security", "ssn", "ssns"},
			validate: func(s string) bool {
				d := stripNonDigits(s)
				if len(d) != 9 {
					return false
				}
				if d == "078051120" || d == "123456789" || d == "219099999" {
					return false
				}
				if d[:3] == "000" || d[:3] == "666" || d[:3] == "900" {
					return false
				}
				if d[3:5] == "00" || d[5:] == "0000" {
					return false
				}
				return true
			},
		},

		// =====================================================================
		// US ITIN — from us_itin_recognizer.py
		// =====================================================================
		{
			label:   "US_ITIN",
			ruleID:  "us_itin_dash",
			pattern: `\b9\d{2}[- ](5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])[- ]\d{4}\b`,
			score:   0.5,
			context: []string{"individual", "taxpayer", "itin", "tax", "payer", "tin"},
		},
		{
			label:      "US_ITIN",
			ruleID:     "us_itin_bare",
			pattern:    `\b9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])\d{4}\b`,
			score:      0.3,
			context:    []string{"individual", "taxpayer", "itin", "tax", "payer", "tin"},
			contextReq: true,
		},

		// =====================================================================
		// US PASSPORT — from us_passport_recognizer.py
		// =====================================================================
		{
			label:      "US_PASSPORT",
			ruleID:     "us_passport_numeric",
			pattern:    `\b\d{9}\b`,
			score:      0.05,
			context:    []string{"passport", "travel", "document", "us passport"},
			contextReq: true,
		},
		{
			label:   "US_PASSPORT",
			ruleID:  "us_passport_alpha",
			pattern: `\b[A-Z]\d{8}\b`,
			score:   0.1,
			context: []string{"passport", "travel", "document", "us passport"},
		},

		// =====================================================================
		// US DRIVER LICENSE — from us_driver_license_recognizer.py
		// (using the alphanumeric pattern, context-required to avoid FPs)
		// =====================================================================
		{
			label:      "US_DRIVER_LICENSE",
			ruleID:     "us_driver_license",
			pattern:    `\b(?:[A-Z]\d{3,6}|[A-Z]\d{5,9}|[A-Z]\d{6,8}|[A-Z]\d{4,8}|[A-Z]\d{9,11}|[A-Z]{1,2}\d{5,6}|[A-Z]{2}\d{2,5}|[A-Z]{2}\d{3,7}|\d{2}[A-Z]{3}\d{5,6}|[A-Z]\d{13,14}|[A-Z]\d{18}|[A-Z]\d{6}R|[A-Z]\d{9}|[A-Z]\d{1,12}|\d{9}[A-Z]|[A-Z]{2}\d{6}[A-Z]|\d{8}[A-Z]{2}|\d{3}[A-Z]{2}\d{4}|[A-Z]\d[A-Z]\d[A-Z]|\d{7,8}[A-Z])\b`,
			score:      0.3,
			context:    []string{"driver", "license", "licence", "permit", "identification", "driving", "dl", "lic"},
			contextReq: true,
		},

		// =====================================================================
		// US BANK — from us_bank_recognizer.py (tightened: 10+ digits, strict context)
		// =====================================================================
		{
			label:      "US_BANK_NUMBER",
			ruleID:     "us_bank_number",
			pattern:    `\b\d{10,17}\b`,
			score:      0.05,
			context:    []string{"account#", "acct", "bank account", "checking", "savings", "routing number"},
			contextReq: true,
		},

		// =====================================================================
		// ABA ROUTING — from aba_routing_recognizer.py
		// =====================================================================
		{
			label:   "ABA_ROUTING",
			ruleID:  "aba_routing_dashed",
			pattern: `\b[0123678]\d{3}-\d{4}-\d\b`,
			score:   0.3,
			context: []string{"aba", "routing", "bankrouting", "transit"},
			validate: func(s string) bool {
				d := stripNonDigits(s)
				return len(d) == 9 && abaChecksum(d)
			},
		},
		{
			label:      "ABA_ROUTING",
			ruleID:     "aba_routing_bare",
			pattern:    `\b[0123678]\d{8}\b`,
			score:      0.05,
			context:    []string{"aba", "routing", "bankrouting", "transit"},
			contextReq: true,
			validate: func(s string) bool {
				return abaChecksum(s)
			},
		},

		// =====================================================================
		// US MEDICAL LICENSE (DEA) — from medical_license_recognizer.py
		// =====================================================================
		{
			label:   "MEDICAL_LICENSE",
			ruleID:  "dea_license",
			pattern: `\b[ABCDEFGHJKLMPRSTUXabcdefghjklmprstux][a-zA-Z]\d{7}\b`,
			score:   0.4,
			context: []string{"medical", "certificate", "dea", "license", "npi", "provider"},
		},

		// =====================================================================
		// US MBI (Medicare Beneficiary Identifier) — from us_mbi_recognizer.py
		// =====================================================================
		{
			label:   "US_MBI",
			ruleID:  "us_mbi_separated",
			pattern: `\b\d[ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY]\d-[ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY]\d-[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY]\d{2}\b`,
			score:   0.5,
			context: []string{"medicare", "mbi", "beneficiary", "cms", "medicaid"},
		},
		{
			label:      "US_MBI",
			ruleID:     "us_mbi_bare",
			pattern:    `\b\d[ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY]\d[ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY]\d[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY]\d{2}\b`,
			score:      0.3,
			context:    []string{"medicare", "mbi", "beneficiary", "cms", "medicaid"},
			contextReq: true,
		},

		// =====================================================================
		// US NPI (National Provider Identifier) — from us_npi_recognizer.py
		// =====================================================================
		{
			label:   "US_NPI",
			ruleID:  "us_npi_separated",
			pattern: `\b[12]\d{3}[ -]\d{3}[ -]\d{3}\b`,
			score:   0.4,
			context: []string{"npi", "national provider", "provider", "provider id", "taxonomy"},
		},
		{
			label:      "US_NPI",
			ruleID:     "us_npi_bare",
			pattern:    `\b[12]\d{9}\b`,
			score:      0.1,
			context:    []string{"npi", "national provider", "provider", "provider id", "taxonomy"},
			contextReq: true,
		},

		// =====================================================================
		// UK NHS — from uk_nhs_recognizer.py
		// =====================================================================
		{
			label:   "UK_NHS",
			ruleID:  "uk_nhs",
			pattern: `\b\d{3}[- ]?\d{3}[- ]?\d{4}\b`,
			score:   0.3,
			context: []string{"national health service", "nhs", "health services authority", "health authority"},
			validate: func(s string) bool {
				d := stripNonDigits(s)
				if len(d) != 10 {
					return false
				}
				return nhsChecksum(d)
			},
			contextReq: true,
		},

		// =====================================================================
		// UK NINO — from uk_nino_recognizer.py
		// =====================================================================
		{
			label:   "UK_NINO",
			ruleID:  "uk_nino",
			pattern: `(?i)\b(?!BG|GB|NK|KN|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b`,
			score:   0.5,
			context: []string{"national insurance", "ni number", "nino"},
		},

		// =====================================================================
		// UK POSTCODE — from uk_postcode_recognizer.py
		// =====================================================================
		{
			label:      "UK_POSTCODE",
			ruleID:     "uk_postcode",
			pattern:    `\b(?:GIR\s?0AA|[A-PR-UWYZ][0-9][ABCDEFGHJKPSTUW]?\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][0-9]{2}\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRVWXY]?\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HK-Y][0-9]{2}\s?[0-9][ABD-HJLNP-UW-Z]{2})\b`,
			score:      0.1,
			context:    []string{"postcode", "post code", "postal code", "zip", "address", "delivery", "mailing"},
			contextReq: true,
		},

		// =====================================================================
		// UK PASSPORT — from uk_passport_recognizer.py
		// =====================================================================
		{
			label:      "UK_PASSPORT",
			ruleID:     "uk_passport",
			pattern:    `\b[A-Z]{2}\d{7}\b`,
			score:      0.1,
			context:    []string{"passport", "travel document", "uk passport", "british passport"},
			contextReq: true,
		},

		// =====================================================================
		// UK DRIVING LICENCE — from uk_driving_licence_recognizer.py
		// =====================================================================
		{
			label:   "UK_DRIVING_LICENCE",
			ruleID:  "uk_driving_licence",
			pattern: `\b[A-Z9]{5}\d(?:0[1-9]|1[0-2]|5[1-9]|6[0-2])(?:0[1-9]|[12]\d|3[01])\d[A-Z9]{2}[A-Z0-9][A-Z]{2}\b`,
			score:   0.5,
			context: []string{"driving licence", "driving license", "driver", "dvla", "licence number", "license number"},
		},

		// =====================================================================
		// CANADA SIN — from ca_sin_recognizer.py
		// =====================================================================
		{
			label:   "CA_SIN",
			ruleID:  "ca_sin",
			pattern: `\b[1-79]\d{2}-\d{3}-\d{3}\b`,
			score:   0.5,
			context: []string{"sin", "social insurance", "canada"},
			validate: func(s string) bool {
				d := stripNonDigits(s)
				return len(d) == 9 && luhn(d)
			},
		},
		{
			label:   "CA_SIN",
			ruleID:  "ca_sin",
			pattern: `\b[1-79]\d{2} \d{3} \d{3}\b`,
			score:   0.5,
			context: []string{"sin", "social insurance", "canada"},
			validate: func(s string) bool {
				d := stripNonDigits(s)
				return len(d) == 9 && luhn(d)
			},
		},

		// =====================================================================
		// AUSTRALIA TFN — from au_tfn_recognizer.py
		// =====================================================================
		{
			label:      "AU_TFN",
			ruleID:     "au_tfn",
			pattern:    `\b\d{3}\s\d{3}\s\d{3}\b`,
			score:      0.1,
			context:    []string{"tax file number", "tfn"},
			contextReq: true,
			validate: func(s string) bool {
				d := stripNonDigits(s)
				if len(d) != 9 {
					return false
				}
				weights := []int{1, 4, 3, 7, 5, 8, 6, 9, 10}
				sum := 0
				for i, w := range weights {
					sum += int(d[i]-'0') * w
				}
				return sum%11 == 0
			},
		},

		// =====================================================================
		// INDIA PAN — from in_pan_recognizer.py
		// =====================================================================
		{
			label:   "IN_PAN",
			ruleID:  "in_pan",
			pattern: `(?i)\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b`,
			score:   0.5,
			context: []string{"permanent account number", "pan", "income tax"},
		},

		// =====================================================================
		// SPAIN NIF — from es_nif_recognizer.py
		// =====================================================================
		{
			label:   "ES_NIF",
			ruleID:  "es_nif",
			pattern: `\b\d{8}[A-Z]\b`,
			score:   0.3,
			context: []string{"dni", "nif", "identificacion", "documento"},
			validate: func(s string) bool {
				if len(s) != 9 {
					return false
				}
				d := stripNonDigits(s[:8])
				if len(d) != 8 {
					return false
				}
				n := 0
				for _, c := range d {
					n = n*10 + int(c-'0')
				}
				table := "TRWAGMYFPDXBNJZSQVHLCKE"
				return s[8] == table[n%23]
			},
		},

		// =====================================================================
		// GERMANY PASSPORT — from de_passport_recognizer.py
		// =====================================================================
		{
			label:      "DE_PASSPORT",
			ruleID:     "de_passport",
			pattern:    `\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{7}\d\b`,
			score:      0.4,
			context:    []string{"reisepass", "passport", "passnummer", "passport number"},
			contextReq: true,
		},

		// =====================================================================
		// SINGAPORE NRIC/FIN — from sg_fin_recognizer.py
		// =====================================================================
		{
			label:   "SG_NRIC_FIN",
			ruleID:  "sg_nric_fin",
			pattern: `(?i)\b[STFGM]\d{7}[A-Z]\b`,
			score:   0.5,
			context: []string{"fin", "nric", "singapore"},
		},

		// =====================================================================
		// GENERIC ID — context-required pattern for customer/employee/member IDs
		// =====================================================================
		{
			label:      "PERSON_ID",
			ruleID:     "person_id_generic",
			pattern:    `(?i)(?:customer|employee|member|patient|policy|claim|case|ref(?:erence)?|order|invoice|ticket|tracking|confirmation|transaction)\s*(?:id|no|number|num|#|:)\s*[:=#]?\s*[A-Z0-9\-]{4,20}\b`,
			score:      0.5,
			context:    []string{},
			contextReq: false,
		},

		// =====================================================================
		// SWIFT/BIC — context-required (bare 8-11 uppercase matches too many words)
		// =====================================================================
		{
			label:      "SWIFT_BIC",
			ruleID:     "swift_bic",
			pattern:    `\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`,
			score:      0.3,
			context:    []string{"swift", "bic", "wire", "routing", "correspondent"},
			contextReq: true,
			validate: func(s string) bool {
				for _, r := range s {
					if r >= '0' && r <= '9' {
						return true
					}
				}
				return false
			},
		},

		// =====================================================================
		// CVV/CVC — keyword-required + payment-card context required
		// =====================================================================
		{
			label:      "CVV",
			ruleID:     "cvv",
			pattern:    `(?i)(?:cvv|cvc|cvv2|cvc2|security\s*code|card\s*verification)\s*[:=]?\s*\d{3,4}\b`,
			score:      0.6,
			context:    []string{"card", "credit", "visa", "mastercard", "amex", "expir", "cardholder", "payment"},
			contextReq: true,
		},

		// =====================================================================
		// PHONE — Presidio uses phonenumbers lib; we use regex patterns
		// =====================================================================
		{label: "PHONE_NUMBER", ruleID: "phone_parens", pattern: `\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}`, score: 0.7},
		{label: "PHONE_NUMBER", ruleID: "phone_dash_dot", pattern: `\b\d{3}[\-\.]\d{3}[\-\.]\d{4}\b`, score: 0.6},
		{label: "PHONE_NUMBER", ruleID: "phone_intl_plus", pattern: `\+\d{1,4}[\s\-.]?\(?\d{1,5}\)?[\s\-.]?\d{2,5}[\s\-.]?\d{2,5}[\s\-.]?\d{0,5}`, score: 0.6},
		{label: "PHONE_NUMBER", ruleID: "phone_leading_zero", pattern: `\b0\d{2,4}[\s.\-]\d{3,8}[\s.\-]?\d{0,6}\b`, score: 0.5, context: []string{"phone", "tel", "mobile", "cell", "call", "fax", "contact"}},
		{label: "PHONE_NUMBER", ruleID: "phone_double_zero", pattern: `\b00\d{2,4}[\s.\-]\d{2,5}[\s\-.]?\d{3,5}[\s\-.]?\d{0,5}\b`, score: 0.5},

		// =====================================================================
		// SECRETS & CREDENTIALS — not in Presidio
		// =====================================================================
		{label: "AWS_ACCESS_KEY", ruleID: "aws_access_key", pattern: `AKIA[0-9A-Z]{16}`, score: 0.9},
		{label: "AWS_SECRET_KEY", ruleID: "aws_secret_key", pattern: `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`, score: 0.9},
		{label: "GCP_API_KEY", ruleID: "gcp_api_key", pattern: `AIza[0-9A-Za-z\-_]{35}`, score: 0.9},
		{label: "PRIVATE_KEY", ruleID: "private_key_pem", pattern: `(?s)-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, score: 1.0},
		{label: "JWT", ruleID: "jwt", pattern: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]+`, score: 0.9},
		{label: "CONNECTION_STRING", ruleID: "connection_string", pattern: `(?i)(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s]+`, score: 0.8},
		{label: "GENERIC_SECRET", ruleID: "generic_secret_kv", pattern: `(?i)(?:password|secret|token|api_key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9/+=\-_]{8,}['"]?`, score: 0.7},
		{label: "GENERIC_SECRET", ruleID: "generic_secret_pwd", pattern: `(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{4,}['"]?`, score: 0.6},

		// =====================================================================
		// PASSWORD — with keyword context, filtering common adjectives
		// =====================================================================
		{
			label:   "PASSWORD",
			ruleID:  "password_prose",
			pattern: `(?i)(?:password|passwd|pwd|passcode)\s*(?:is|was|:)\s*(?!(?:valid|invalid|temporary|required|optional|incorrect|correct|wrong|right|expired|changed|reset|secure|strong|weak|empty|null|blank|missing|set|enabled|disabled|locked|unlocked)\b)[^\s,;]{4,40}`,
			score:   0.7,
		},

		// =====================================================================
		// IMEI — 15 digits with dash separators
		// =====================================================================
		{label: "IMEI", ruleID: "imei", pattern: `\b\d{2}-\d{6}-\d{6}-\d{1}\b`, score: 0.7},

		// =====================================================================
		// CC-EXPIRY — credit card expiration dates
		// =====================================================================
		{label: "CC_EXPIRY", ruleID: "cc_expiry", pattern: `\b(?:0[1-9]|1[0-2])\/(?:2[0-9]|3[0-9])\b`, score: 0.4, context: []string{"card", "credit", "expir", "exp", "valid"}},

		// =====================================================================
		// INSURANCE/REGISTRATION IDs — keyword-required
		// =====================================================================
		{label: "INSURANCE_ID", ruleID: "insurance_id", pattern: `(?i)(?:insurance|policy|health\s*plan|member)\s*(?:no|number|id|#|:)\s*[A-Z]{0,3}\d{6,12}\b`, score: 0.6},
		{label: "REGISTRATION_ID", ruleID: "registration_id_generic", pattern: `(?i)(?:student|registration|reg|enrollment)\s*(?:no|number|id|#|:)\s*(?=[A-Z0-9\-]*\d)[A-Z0-9\-]{5,15}\b`, score: 0.6},

		// =====================================================================
		// IBAN — simpler pattern for common format (complements Presidio's IBAN)
		// =====================================================================
		{label: "IBAN_CODE", ruleID: "iban_simple", pattern: `\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b`, score: 0.5, context: []string{"iban", "bank", "account"}},

		// =====================================================================
		// CREDIT CARD — separated format (4x4 digits)
		// =====================================================================
		{label: "CREDIT_CARD", ruleID: "credit_card_4x4", pattern: `\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b`, score: 0.7},

		// =====================================================================
		// HEALTH PLAN BENEFICIARY — Tier 1, structured IDs
		// =====================================================================
		{label: "HEALTH_PLAN_ID", ruleID: "health_plan_id", pattern: `(?i)(?:health\s*plan|beneficiary|hpb|hic|hicn|subscriber)\s*(?:id|no|number|num|#|:)\s*[:=#]?\s*[A-Z0-9\-]{6,15}\b`, score: 0.7},

		// =====================================================================
		// MEDICAL RECORD NUMBER — Tier 1, require actual ID value (digit-containing)
		// =====================================================================
		{
			label:   "MEDICAL_RECORD",
			ruleID:  "medical_record_mrn",
			pattern: `(?i)(?:medical\s*record|mrn|chart|patient\s*id|medical\s*id)\s*(?:no|number|num|#|:)?\s*[:=#]?\s*(?=[A-Z0-9\-]*\d)[A-Z0-9\-]{4,15}\b`,
			score:   0.7,
		},

		// =====================================================================
		// BIOMETRIC IDENTIFIER — Tier 1, require actual hash/ID value (digit-containing)
		// =====================================================================
		{
			label:   "BIOMETRIC_ID",
			ruleID:  "biometric_id",
			pattern: `(?i)(?:biometric|fingerprint|face\s*id|retina|iris)\s*(?:id|hash|data|scan|template|no|number|#|:)\s*[:=#]?\s*(?=[A-Za-z0-9\-_]*\d)[A-Za-z0-9\-_]{8,64}\b`,
			score:   0.6,
		},

		// =====================================================================
		// LICENSE PLATE — Tier 1, common formats
		// =====================================================================
		{
			label:      "LICENSE_PLATE",
			ruleID:     "license_plate",
			pattern:    `(?i)(?:license\s*plate|plate\s*(?:no|number|#)|vehicle\s*(?:reg|registration)|vrn)\s*[:=#]?\s*[A-Z0-9]{2,3}[\s\-]?[A-Z0-9]{2,4}[\s\-]?[A-Z0-9]{1,4}\b`,
			score:      0.6,
			context:    []string{},
			contextReq: false,
		},

		// =====================================================================
		// URL WITH TOKENS — Tier 2, URLs containing session/auth tokens
		// =====================================================================
		{label: "URL_WITH_TOKEN", ruleID: "url_with_token", pattern: `https?://[^\s<>"')\]]*[?&](?:token|session|auth|key|api_key|access_token|sid|csrf|jwt)=[^\s<>"')\]&]+`, score: 0.8},

		// =====================================================================
		// SSN — separated formats
		// =====================================================================
		{label: "US_SSN", ruleID: "us_ssn_dash", pattern: `\b\d{3}-\d{2}-\d{4}\b`, score: 0.5, context: []string{"social", "security", "ssn"}},
		{label: "US_SSN", ruleID: "us_ssn_space", pattern: `\b\d{3}\s\d{2}\s\d{4}\b`, score: 0.5, context: []string{"social", "security", "ssn"}},
	}

	var out []patternDef
	for _, d := range defs {
		re, err := regexp.Compile(d.pattern)
		if err != nil {
			continue
		}
		if d.ruleID != "" && enabled != nil && !enabled(d.ruleID) {
			continue
		}
		out = append(out, patternDef{
			label:      d.label,
			ruleID:     d.ruleID,
			re:         re,
			score:      d.score,
			context:    d.context,
			validate:   d.validate,
			contextReq: d.contextReq,
		})
	}
	return out
}

// luhn implements the Luhn checksum algorithm.
func luhn(digits string) bool {
	n := len(digits)
	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// ibanCheckDigit validates an IBAN check digit (mod 97).
func ibanCheckDigit(iban string) bool {
	if len(iban) < 5 {
		return false
	}
	rearranged := iban[4:] + iban[:4]
	var numeric strings.Builder
	for _, r := range strings.ToUpper(rearranged) {
		if r >= '0' && r <= '9' {
			numeric.WriteRune(r)
		} else if r >= 'A' && r <= 'Z' {
			n := int(r-'A') + 10
			if n >= 10 {
				numeric.WriteByte(byte(n/10) + '0')
			}
			numeric.WriteByte(byte(n%10) + '0')
		} else {
			return false
		}
	}
	s := numeric.String()
	rem := 0
	for _, c := range s {
		rem = (rem*10 + int(c-'0')) % 97
	}
	return rem == 1
}

// abaChecksum validates a US ABA routing number.
func abaChecksum(digits string) bool {
	if len(digits) != 9 {
		return false
	}
	weights := []int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0
	for i, w := range weights {
		sum += int(digits[i]-'0') * w
	}
	return sum%10 == 0
}

// nhsChecksum validates a UK NHS number.
func nhsChecksum(digits string) bool {
	if len(digits) != 10 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(digits[i]-'0') * (10 - i)
	}
	check := 11 - (sum % 11)
	if check == 11 {
		check = 0
	}
	if check == 10 {
		return false
	}
	return check == int(digits[9]-'0')
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
