package scanner

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type PipelineReport struct {
	Findings     []Finding           `json:"findings"`
	LayerResults []PipelineLayerInfo `json:"layer_results"`
	TotalMs      int64               `json:"total_ms"`
}

type PipelineLayerInfo struct {
	Name          string `json:"name"`
	FindingsCount int    `json:"findings_count"`
	LatencyMs     int64  `json:"latency_ms"`
	Skipped       bool   `json:"skipped"`
	SkipReason    string `json:"skip_reason,omitempty"`
}

type Pipeline struct {
	layers    []Layer
	timeoutMs int
}

func NewPipeline(layers ...Layer) *Pipeline {
	return &Pipeline{layers: layers}
}

func (p *Pipeline) SetTimeout(ms int) {
	p.timeoutMs = ms
}

func (p *Pipeline) Scan(text string) (*PipelineReport, error) {
	start := time.Now()
	report := &PipelineReport{}
	currentText := text
	var offsets []offsetEntry

	for _, layer := range p.layers {
		info := PipelineLayerInfo{Name: layer.Name()}

		if !layer.Ready() {
			info.Skipped = true
			info.SkipReason = "not ready"
			report.LayerResults = append(report.LayerResults, info)
			continue
		}

		layerStart := time.Now()
		result, err := p.scanWithTimeout(layer, currentText)
		info.LatencyMs = time.Since(layerStart).Milliseconds()

		if err != nil {
			info.Skipped = true
			info.SkipReason = err.Error()
			report.LayerResults = append(report.LayerResults, info)
			continue
		}

		if len(result.Findings) > 0 {
			for i := range result.Findings {
				result.Findings[i].Start = toOriginalPos(result.Findings[i].Start, offsets)
				result.Findings[i].End = toOriginalPos(result.Findings[i].End, offsets)
			}
			report.Findings = append(report.Findings, result.Findings...)
			currentText, offsets = applyRedactions(text, report.Findings)
		}

		info.FindingsCount = len(result.Findings)
		report.LayerResults = append(report.LayerResults, info)
	}

	report.TotalMs = time.Since(start).Milliseconds()
	return report, nil
}

func (p *Pipeline) scanWithTimeout(layer Layer, text string) (*ScanResult, error) {
	if p.timeoutMs <= 0 {
		return layer.Scan(text)
	}

	type scanOut struct {
		result *ScanResult
		err    error
	}
	ch := make(chan scanOut, 1)
	go func() {
		r, e := layer.Scan(text)
		ch <- scanOut{r, e}
	}()

	timer := time.NewTimer(time.Duration(p.timeoutMs) * time.Millisecond)
	defer timer.Stop()

	select {
	case out := <-ch:
		return out.result, out.err
	case <-timer.C:
		return nil, fmt.Errorf("timeout after %dms", p.timeoutMs)
	}
}

type offsetEntry struct {
	origStart int
	origEnd   int
	newLen    int
}

func applyRedactions(text string, findings []Finding) (string, []offsetEntry) {
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Start < sorted[j].Start })

	var b strings.Builder
	var entries []offsetEntry
	prev := 0
	for _, f := range sorted {
		if f.Start < prev {
			continue
		}
		if f.Start > len(text) || f.End > len(text) || f.Start >= f.End {
			continue
		}
		b.WriteString(text[prev:f.Start])
		replacement := fmt.Sprintf("[REDACTED-%s]", f.Label)
		b.WriteString(replacement)
		entries = append(entries, offsetEntry{f.Start, f.End, len(replacement)})
		prev = f.End
	}
	b.WriteString(text[prev:])
	return b.String(), entries
}

func toOriginalPos(pos int, offsets []offsetEntry) int {
	shift := 0
	for _, e := range offsets {
		redactedStart := e.origStart + shift
		if pos <= redactedStart {
			break
		}
		redactedEnd := redactedStart + e.newLen
		if pos >= redactedEnd {
			shift += e.newLen - (e.origEnd - e.origStart)
		} else {
			return e.origStart
		}
	}
	return pos - shift
}

// Reconfigurable is implemented by layers that support runtime
// reconfiguration of their rule set. The argument is a per-rule enabled
// predicate; layers translate it to their own internal state.
type Reconfigurable interface {
	Reconfigure(enabled func(ruleID string) bool)
}

// Reconfigure forwards the predicate to every layer that implements
// Reconfigurable. Layers that don't implement it are skipped silently.
func (p *Pipeline) Reconfigure(enabled func(ruleID string) bool) {
	for _, l := range p.layers {
		if r, ok := l.(Reconfigurable); ok {
			r.Reconfigure(enabled)
		}
	}
}
