package gliner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redactrai/redactr/internal/scanner"
)

type DetectRequest struct {
	Text string `json:"text"`
}

type DetectResponse struct {
	Entities []Entity `json:"entities"`
}

type Entity struct {
	Text  string  `json:"text"`
	Label string  `json:"label"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Score float64 `json:"score"`
}

type glinerState struct {
	suppressLabels map[string]bool
}

type Client struct {
	baseURL            string
	client             *http.Client
	ready              atomic.Bool
	minConfidence      float64
	minLength          int
	state              atomic.Pointer[glinerState]
	labelMinConfidence map[string]float64
}

func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:       baseURL,
		minConfidence: 0.5,
		minLength:     2,
		labelMinConfidence: map[string]float64{
			"PERSON":        0.80,
			"PASSWORD":      0.85,
			"CREDIT_CARD":   0.80,
			"ADDRESS":       0.75,
			"NATIONAL_ID":   0.80,
			"IP_ADDRESS":    0.75,
			"DATE_OF_BIRTH": 0.75,
			"EMAIL":         0.70,
			"BANK_ACCOUNT":  0.75,
		},
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	c.state.Store(&glinerState{
		suppressLabels: map[string]bool{
			"ORGANIZATION":      true,
			"FINANCIAL_ACCOUNT": true,
			"USERNAME":          true,
			"LOCATION":          true,
			"TAX_ID":            true,
			"LICENSE_PLATE":     true,
		},
	})
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type Option func(*Client)

func WithMinConfidence(v float64) Option {
	return func(c *Client) { c.minConfidence = v }
}

func WithMinLength(v int) Option {
	return func(c *Client) { c.minLength = v }
}

func WithSuppressLabels(labels []string) Option {
	return func(c *Client) {
		m := make(map[string]bool, len(labels))
		for _, l := range labels {
			m[l] = true
		}
		c.state.Store(&glinerState{suppressLabels: m})
	}
}

func (c *Client) Name() string { return "gliner" }

func (c *Client) Ready() bool {
	return c.ready.Load()
}

func (c *Client) SetBaseURL(url string) {
	c.baseURL = url
}

func (c *Client) SetReady(ready bool) {
	c.ready.Store(ready)
}

// SetEnabled atomically installs a new label-suppression map derived
// from the current snapshot plus the byLabel overrides. Labels not in
// byLabel keep their previous suppression state.
//
// Mapping from rule IDs to GLiNER labels (used by Reconfigure):
//
//	email_gliner            → EMAIL
//	person_gliner           → PERSON
//	address_gliner          → ADDRESS
//	dob_gliner              → DATE_OF_BIRTH
//	ip_gliner               → IP_ADDRESS
//	gliner_national_id_dup  → NATIONAL_ID
func (c *Client) SetEnabled(byLabel map[string]bool) {
	cur := c.state.Load()
	next := make(map[string]bool, len(cur.suppressLabels)+len(byLabel))
	for k, v := range cur.suppressLabels {
		next[k] = v
	}
	for label, on := range byLabel {
		if on {
			delete(next, label)
		} else {
			next[label] = true
		}
	}
	c.state.Store(&glinerState{suppressLabels: next})
}

// Reconfigure translates a per-rule-ID enabled predicate into the
// GLiNER label suppression map. Rule IDs not associated with a GLiNER
// label have no effect.
func (c *Client) Reconfigure(enabled func(string) bool) {
	c.SetEnabled(map[string]bool{
		"EMAIL":         enabled("email_gliner"),
		"PERSON":        enabled("person_gliner"),
		"ADDRESS":       enabled("address_gliner"),
		"DATE_OF_BIRTH": enabled("dob_gliner"),
		"IP_ADDRESS":    enabled("ip_gliner"),
		"NATIONAL_ID":   enabled("gliner_national_id_dup"),
	})
}

func (c *Client) HealthCheck() bool {
	resp, err := c.client.Get(c.baseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result["status"] == "ready"
}

func (c *Client) Scan(text string) (*scanner.ScanResult, error) {
	if !c.Ready() {
		return &scanner.ScanResult{}, nil
	}

	start := time.Now()

	reqBody, err := json.Marshal(DetectRequest{Text: text})
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(c.baseURL+"/detect", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("gliner sidecar request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gliner sidecar returned status %d", resp.StatusCode)
	}

	var detectResp DetectResponse
	if err := json.NewDecoder(resp.Body).Decode(&detectResp); err != nil {
		return nil, err
	}

	state := c.state.Load()
	var findings []scanner.Finding
	for _, entity := range detectResp.Entities {
		minConf := c.minConfidence
		if labelConf, ok := c.labelMinConfidence[entity.Label]; ok {
			minConf = labelConf
		}
		if entity.Score < minConf {
			continue
		}
		if len(entity.Text) < c.minLength {
			continue
		}
		if state.suppressLabels[entity.Label] {
			continue
		}
		if entity.Label == "PERSON" && isGenericRole(entity.Text) {
			continue
		}
		if isPlaceholder(entity.Text) {
			continue
		}
		if entity.Label == "MEDICAL_RECORD" && !containsDigit(entity.Text) {
			continue
		}
		if entity.Label == "PASSWORD" && len(entity.Text) < 8 {
			continue
		}
		if entity.Label == "PASSWORD" && isCommonWord(entity.Text) {
			continue
		}
		if entity.Label == "IP_ADDRESS" && !isDottedQuad(entity.Text) {
			continue
		}
		if entity.Label == "NATIONAL_ID" && !containsDigit(entity.Text) {
			continue
		}
		if entity.Label == "EMAIL" && !strings.Contains(entity.Text, "@") {
			continue
		}
		if strings.Contains(entity.Text, "__") {
			continue
		}
		if entity.Label == "IBAN" && !containsDigit(entity.Text) {
			continue
		}
		findings = append(findings, scanner.Finding{
			Label:      entity.Label,
			Value:      entity.Text,
			Start:      entity.Start,
			End:        entity.End,
			Confidence: entity.Score,
			Layer:      "gliner",
		})
	}

	return &scanner.ScanResult{
		Findings: findings,
		LayerMs:  time.Since(start).Milliseconds(),
	}, nil
}

var genericRoles = map[string]bool{
	"patient": true, "donor": true, "inspector": true, "insured": true,
	"applicant": true, "employee": true, "customer": true, "client": true,
	"user": true, "owner": true, "holder": true, "member": true,
	"resident": true, "caller": true, "driver": true, "traveler": true,
	"buyer": true, "seller": true, "you": true, "your": true,
	"tenant": true, "landlord": true, "borrower": true, "lender": true,
	"claimant": true, "beneficiary": true, "subscriber": true,
	"vendor": true, "contractor": true, "debtor": true, "creditor": true,
	"policyholder": true, "insurer": true, "underwriter": true,
	"guarantor": true, "mortgagor": true, "mortgagee": true,
	"plaintiff": true, "defendant": true, "petitioner": true,
	"respondent": true, "assignee": true, "assignor": true,
	"guest": true, "investors": true, "investor": true, "advisor": true,
	"manager": true, "analyst": true, "officer": true, "director": true,
	"administrator": true, "coordinator": true, "specialist": true,
	"supervisor": true, "consultant": true, "representative": true,
	"agent": true, "broker": true, "examiner": true, "reviewer": true,
	"healthcare provider": true, "provider": true, "intruder": true,
	"project manager": true, "clinical trial coordinator": true,
	"licensee": true, "licensor": true, "licensees": true,
	"payor": true, "payee": true, "registrant": true,
}

var commonWords = map[string]bool{
	"temporary": true, "password": true, "default": true, "admin": true,
	"test": true, "temp": true, "root": true, "null": true, "none": true,
	"empty": true, "blank": true, "invalid": true, "expired": true,
	"reset": true, "new": true, "old": true, "current": true,
	"temporary password": true, "bm": true,
}

func isCommonWord(text string) bool {
	return commonWords[strings.ToLower(strings.TrimSpace(text))]
}

func isDottedQuad(text string) bool {
	parts := strings.Split(strings.TrimSpace(text), ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func isGenericRole(text string) bool {
	return genericRoles[strings.ToLower(strings.TrimSpace(text))]
}

var descriptiveTerms = map[string]bool{
	"password": true, "pin": true, "passcode": true,
	"medical history": true, "vitals": true, "medical report": true,
	"vaccination record": true, "immunization records": true, "immunization record": true,
	"unknown account": true, "primary account": true, "bank account": true,
	"follow-up appointment": true, "detailed report": true,
	"hepatitis a": true, "hepatitis b": true, "hepatitis c": true,
	"account number": true, "social security": true,
	"credit card": true, "debit card": true,
	"health insurance": true, "life insurance": true,
	"date of birth": true, "place of birth": true,
	"tax return": true, "tax id": true,
}

func containsDigit(text string) bool {
	for _, r := range text {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func isPlaceholder(text string) bool {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "[") || strings.HasPrefix(t, "<") || strings.HasPrefix(t, "{") {
		return true
	}
	if strings.Contains(t, "[") || strings.Contains(t, "]") {
		return true
	}
	lower := strings.ToLower(t)
	if descriptiveTerms[lower] {
		return true
	}
	if strings.HasPrefix(lower, "your ") || strings.HasSuffix(lower, " name") ||
		strings.HasSuffix(lower, " address") || strings.HasSuffix(lower, " number") {
		return true
	}
	return false
}
