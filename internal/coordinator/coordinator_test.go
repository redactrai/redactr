package coordinator

import (
	"testing"

	"github.com/redactrai/redactr/internal/fileblock"
	"github.com/redactrai/redactr/internal/scanner"
)

type mockLayer struct {
	name     string
	ready    bool
	findings []scanner.Finding
}

func (m *mockLayer) Name() string { return m.name }
func (m *mockLayer) Ready() bool  { return m.ready }
func (m *mockLayer) Scan(text string) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{Findings: m.findings, LayerMs: 1}, nil
}

func TestCoordinatorScanAndRedact(t *testing.T) {
	layer := &mockLayer{
		name:  "regex",
		ready: true,
		findings: []scanner.Finding{
			{Label: "EMAIL", Value: "user@test.com", Start: 9, End: 22, Layer: "regex"},
		},
	}

	fb := fileblock.New([]string{".env"}, true)
	cache := scanner.NewCache(100)
	pipeline := scanner.NewPipeline(layer)
	coord := New(pipeline, cache, fb)

	text := "contact: user@test.com please"
	redacted, report, err := coord.ScanAndRedact(text)
	if err != nil {
		t.Fatalf("ScanAndRedact error: %v", err)
	}

	expected := "contact: [REDACTED-EMAIL] please"
	if redacted != expected {
		t.Errorf("expected %q, got %q", expected, redacted)
	}
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(report.Findings))
	}
}

func TestCoordinatorCacheHit(t *testing.T) {
	callCount := 0
	layer := &countingLayer{
		name:  "regex",
		ready: true,
		count: &callCount,
	}

	fb := fileblock.New([]string{".env"}, true)
	cache := scanner.NewCache(100)
	pipeline := scanner.NewPipeline(layer)
	coord := New(pipeline, cache, fb)

	coord.ScanAndRedact("same text")
	coord.ScanAndRedact("same text")

	if callCount != 1 {
		t.Errorf("expected 1 scan call (cached), got %d", callCount)
	}
}

type countingLayer struct {
	name  string
	ready bool
	count *int
}

func (c *countingLayer) Name() string { return c.name }
func (c *countingLayer) Ready() bool  { return c.ready }
func (c *countingLayer) Scan(text string) (*scanner.ScanResult, error) {
	*c.count++
	return &scanner.ScanResult{}, nil
}

func TestCoordinatorCleanText(t *testing.T) {
	layer := &mockLayer{name: "regex", ready: true, findings: nil}
	fb := fileblock.New([]string{".env"}, true)
	cache := scanner.NewCache(100)
	coord := New(scanner.NewPipeline(layer), cache, fb)

	redacted, _, err := coord.ScanAndRedact("clean code with no PII")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if redacted != "clean code with no PII" {
		t.Errorf("expected unchanged text, got %q", redacted)
	}
}

func TestCoordinatorReconfigureInvalidatesCache(t *testing.T) {
	pipeline := scanner.NewPipeline()
	cache := scanner.NewCache(10)
	fb := fileblock.New([]string{".env"}, true)
	c := New(pipeline, cache, fb)

	if _, _, err := c.ScanAndRedact("hello world"); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if c.CacheStats().Size != 1 {
		t.Fatalf("expected cache size 1 after a scan; got %d", c.CacheStats().Size)
	}

	c.Reconfigure(func(string) bool { return true }, []string{".key"}, false)

	if c.CacheStats().Size != 0 {
		t.Errorf("Reconfigure should invalidate cache; got size=%d", c.CacheStats().Size)
	}
	if fb.IsBlockedFile("/x.env") {
		t.Error(".env should no longer be blocked after reconfigure")
	}
	if !fb.IsBlockedFile("/x.key") {
		t.Error(".key should be blocked after reconfigure")
	}
}
