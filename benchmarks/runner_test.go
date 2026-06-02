package benchmarks

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/redactrai/redactr/internal/coordinator"
	"github.com/redactrai/redactr/internal/fileblock"
	"github.com/redactrai/redactr/internal/scanner"
	"github.com/redactrai/redactr/internal/scanner/contextgate"
	"github.com/redactrai/redactr/internal/scanner/entropy"
	"github.com/redactrai/redactr/internal/scanner/regex"
)

type sample struct {
	Input          string   `json:"input"`
	ExpectedLabels []string `json:"expected_labels"`
	Description    string   `json:"description"`
}

func loadSamples(t testing.TB) []sample {
	data, err := os.ReadFile("testdata/pii_samples.json")
	if err != nil {
		t.Fatalf("load samples: %v", err)
	}
	var samples []sample
	json.Unmarshal(data, &samples)
	return samples
}

func buildCoordinator() *coordinator.Coordinator {
	regexLayer := regex.New(regex.DefaultPatterns(), nil)
	entropyLayer := entropy.New(4.5, 20)
	gateLayer := contextgate.New()
	pipeline := scanner.NewPipeline(regexLayer, entropyLayer, gateLayer)
	cache := scanner.NewCache(10000)
	fb := fileblock.New([]string{".env", ".tfstate"}, true)
	return coordinator.New(pipeline, cache, fb)
}

func TestDetectionAccuracy(t *testing.T) {
	samples := loadSamples(t)
	coord := buildCoordinator()

	for _, s := range samples {
		t.Run(s.Description, func(t *testing.T) {
			_, report, err := coord.ScanAndRedact(s.Input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}

			foundLabels := make(map[string]bool)
			for _, f := range report.Findings {
				foundLabels[f.Label] = true
			}

			for _, expected := range s.ExpectedLabels {
				if !foundLabels[expected] {
					t.Errorf("missed expected label %q in %q", expected, s.Description)
				}
			}

			if len(s.ExpectedLabels) == 0 && len(report.Findings) > 0 {
				t.Errorf("false positive: expected no findings, got %d", len(report.Findings))
			}
		})
	}
}

func BenchmarkScanPipeline(b *testing.B) {
	samples := loadSamples(b)
	coord := buildCoordinator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range samples {
			coord.ScanAndRedact(s.Input)
		}
	}
}

func BenchmarkScanPipelineCached(b *testing.B) {
	samples := loadSamples(b)
	coord := buildCoordinator()

	for _, s := range samples {
		coord.ScanAndRedact(s.Input)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range samples {
			coord.ScanAndRedact(s.Input)
		}
	}
}
