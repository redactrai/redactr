package scanner

import (
	"testing"
)

type mockLayer struct {
	name     string
	findings []Finding
	ready    bool
}

func (m *mockLayer) Name() string { return m.name }
func (m *mockLayer) Ready() bool  { return m.ready }
func (m *mockLayer) Scan(text string) (*ScanResult, error) {
	return &ScanResult{Findings: m.findings, LayerMs: 1}, nil
}

func TestPipelineRunsAllLayers(t *testing.T) {
	p := NewPipeline(
		&mockLayer{name: "layer1", ready: true, findings: []Finding{
			{Label: "EMAIL", Value: "test@test.com", Start: 0, End: 13, Layer: "layer1"},
		}},
		&mockLayer{name: "layer2", ready: true, findings: []Finding{
			{Label: "ENTROPY-SECRET", Value: "aGVsbG8gd29ybGQ=", Start: 20, End: 37, Layer: "layer2"},
		}},
	)

	report, err := p.Scan("test@test.com hello aGVsbG8gd29ybGQ=")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(report.Findings))
	}
	if len(report.LayerResults) != 2 {
		t.Errorf("expected 2 layer results, got %d", len(report.LayerResults))
	}
}

func TestPipelineSkipsUnreadyLayers(t *testing.T) {
	p := NewPipeline(
		&mockLayer{name: "ready", ready: true, findings: []Finding{
			{Label: "EMAIL", Value: "x@y.com", Start: 0, End: 7, Layer: "ready"},
		}},
		&mockLayer{name: "not-ready", ready: false, findings: []Finding{
			{Label: "PERSON", Value: "John", Start: 10, End: 14, Layer: "not-ready"},
		}},
	)

	report, err := p.Scan("x@y.com hi John")
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding (skipped unready), got %d", len(report.Findings))
	}
	if len(report.LayerResults) != 2 {
		t.Errorf("expected 2 layer results (including skipped), got %d", len(report.LayerResults))
	}
	if !report.LayerResults[1].Skipped {
		t.Error("expected second layer marked as skipped")
	}
}

func TestPipelineReconfigureFanOut(t *testing.T) {
	var saw []string
	fakeA := &fakeReconfigurable{name: "A", onReconfigure: func() { saw = append(saw, "A") }}
	fakeB := &fakeReconfigurable{name: "B", onReconfigure: func() { saw = append(saw, "B") }}
	nonReconf := &fakeNonReconfigurable{name: "C"}

	p := NewPipeline(fakeA, nonReconf, fakeB)
	p.Reconfigure(func(string) bool { return true })

	if len(saw) != 2 || saw[0] != "A" || saw[1] != "B" {
		t.Errorf("expected [A B] called in pipeline order; got %v", saw)
	}
}

type fakeReconfigurable struct {
	name          string
	onReconfigure func()
}

func (f *fakeReconfigurable) Name() string                     { return f.name }
func (f *fakeReconfigurable) Ready() bool                      { return true }
func (f *fakeReconfigurable) Scan(string) (*ScanResult, error) { return &ScanResult{}, nil }
func (f *fakeReconfigurable) Reconfigure(_ func(string) bool)  { f.onReconfigure() }

type fakeNonReconfigurable struct {
	name string
}

func (f *fakeNonReconfigurable) Name() string                     { return f.name }
func (f *fakeNonReconfigurable) Ready() bool                      { return true }
func (f *fakeNonReconfigurable) Scan(string) (*ScanResult, error) { return &ScanResult{}, nil }
