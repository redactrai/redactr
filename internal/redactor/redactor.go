package redactor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rakeshguha/redactr/internal/scanner"
)

type RedactionResult struct {
	Text    string             `json:"text"`
	Applied []AppliedRedaction `json:"applied"`
}

type AppliedRedaction struct {
	Label    string `json:"label"`
	Original string `json:"original"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

func Redact(text string, findings []scanner.Finding) *RedactionResult {
	if len(findings) == 0 {
		return &RedactionResult{Text: text}
	}

	deduped := dedup(findings)

	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].Start < deduped[j].Start
	})

	var b strings.Builder
	var applied []AppliedRedaction
	prev := 0

	for _, f := range deduped {
		if f.Start < prev {
			continue
		}
		b.WriteString(text[prev:f.Start])
		label := fmt.Sprintf("[REDACTED-%s]", f.Label)
		b.WriteString(label)
		applied = append(applied, AppliedRedaction{
			Label:    label,
			Original: f.Value,
			Start:    f.Start,
			End:      f.End,
		})
		prev = f.End
	}
	b.WriteString(text[prev:])

	return &RedactionResult{Text: b.String(), Applied: applied}
}

func dedup(findings []scanner.Finding) []scanner.Finding {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Start == findings[j].Start {
			return (findings[i].End - findings[i].Start) > (findings[j].End - findings[j].Start)
		}
		return findings[i].Start < findings[j].Start
	})

	var result []scanner.Finding
	for _, f := range findings {
		overlaps := false
		for _, existing := range result {
			if f.Start >= existing.Start && f.End <= existing.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			result = append(result, f)
		}
	}
	return result
}
