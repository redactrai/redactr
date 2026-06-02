package opf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/rakeshguha/redactr/internal/scanner"
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

// OPF labels → our internal labels
var labelMap = map[string]string{
	"PRIVATE_PERSON":  "PERSON",
	"PRIVATE_EMAIL":   "EMAIL",
	"PRIVATE_PHONE":   "PHONE",
	"PRIVATE_ADDRESS": "ADDRESS",
	"PRIVATE_URL":     "URL",
	"PRIVATE_DATE":    "DATE_OF_BIRTH",
	"ACCOUNT_NUMBER":  "ACCOUNT_NUMBER",
	"SECRET":          "SECRET",
}

type Client struct {
	baseURL string
	client  *http.Client
	ready   atomic.Bool
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Name() string { return "opf" }

func (c *Client) Ready() bool {
	return c.ready.Load()
}

func (c *Client) SetBaseURL(url string) {
	c.baseURL = url
}

func (c *Client) SetReady(ready bool) {
	c.ready.Store(ready)
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
		return nil, fmt.Errorf("opf sidecar request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opf sidecar returned status %d", resp.StatusCode)
	}

	var detectResp DetectResponse
	if err := json.NewDecoder(resp.Body).Decode(&detectResp); err != nil {
		return nil, err
	}

	var findings []scanner.Finding
	for _, entity := range detectResp.Entities {
		if len(entity.Text) < 3 {
			continue
		}
		if strings.Contains(entity.Text, "REDACTED") {
			continue
		}
		if strings.HasPrefix(entity.Text, "[") || strings.HasPrefix(entity.Text, "<") {
			continue
		}
		if strings.HasPrefix(entity.Text, "$.") || strings.HasPrefix(entity.Text, "/") {
			continue
		}
		if isNonsenseToken(entity.Text) {
			continue
		}
		upper := strings.ToUpper(entity.Label)
		if upper == "PRIVATE_PERSON" && !looksLikeName(entity.Text) {
			continue
		}
		if upper == "SECRET" && len(entity.Text) < 8 {
			continue
		}
		if upper == "PRIVATE_ADDRESS" && len(entity.Text) < 8 {
			continue
		}
		if upper == "PRIVATE_DATE" && len(entity.Text) < 6 {
			continue
		}
		if upper == "ACCOUNT_NUMBER" && len(entity.Text) < 5 {
			continue
		}
		label := entity.Label
		if mapped, ok := labelMap[label]; ok {
			label = mapped
		}
		findings = append(findings, scanner.Finding{
			Label:      label,
			Value:      entity.Text,
			Start:      entity.Start,
			End:        entity.End,
			Confidence: entity.Score,
			Layer:      "opf",
		})
	}

	return &scanner.ScanResult{
		Findings: findings,
		LayerMs:  time.Since(start).Milliseconds(),
	}, nil
}

func looksLikeName(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return false
	}
	if strings.Contains(s, "<") || strings.Contains(s, ">") || strings.Contains(s, "{") {
		return false
	}
	// Must start with an uppercase letter
	runes := []rune(s)
	if !unicode.IsUpper(runes[0]) {
		return false
	}
	// All characters should be letters, spaces, hyphens, periods, or apostrophes
	for _, r := range s {
		if !unicode.IsLetter(r) && r != ' ' && r != '-' && r != '.' && r != '\'' {
			return false
		}
	}
	return true
}

func isNonsenseToken(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return true
	}
	vowels := 0
	letters := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
			switch unicode.ToLower(r) {
			case 'a', 'e', 'i', 'o', 'u':
				vowels++
			}
		}
	}
	if letters > 3 && vowels == 0 {
		return true
	}
	if letters > 5 && float64(vowels)/float64(letters) < 0.1 {
		return true
	}
	return false
}
