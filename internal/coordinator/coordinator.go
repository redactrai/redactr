package coordinator

import (
	"strings"

	"github.com/redactrai/redactr/internal/fileblock"
	"github.com/redactrai/redactr/internal/redactor"
	"github.com/redactrai/redactr/internal/scanner"
)

type Coordinator struct {
	pipeline     *scanner.Pipeline
	cache        *scanner.Cache
	fb           *fileblock.Blocker
	allowedWords map[string]bool
}

func New(pipeline *scanner.Pipeline, cache *scanner.Cache, fb *fileblock.Blocker) *Coordinator {
	return &Coordinator{
		pipeline: pipeline,
		cache:    cache,
		fb:       fb,
	}
}

func (c *Coordinator) SetAllowedWords(words []string) {
	c.allowedWords = make(map[string]bool, len(words))
	for _, w := range words {
		c.allowedWords[strings.ToLower(w)] = true
	}
}

func (c *Coordinator) ScanAndRedact(text string) (string, *scanner.PipelineReport, error) {
	if redacted, report, hit := c.cache.Get(text); hit {
		return redacted, report, nil
	}

	report, err := c.pipeline.Scan(text)
	if err != nil {
		return text, nil, err
	}

	if len(c.allowedWords) > 0 {
		filtered := report.Findings[:0]
		for _, f := range report.Findings {
			if !c.allowedWords[strings.ToLower(f.Value)] {
				filtered = append(filtered, f)
			}
		}
		report.Findings = filtered
	}

	result := redactor.Redact(text, report.Findings)

	c.cache.Put(text, result.Text, report)

	return result.Text, report, nil
}

func (c *Coordinator) InvalidateCache() {
	c.cache.Invalidate()
}

func (c *Coordinator) CacheStats() scanner.CacheStats {
	return c.cache.Stats()
}

// Reconfigure propagates a new rule-enabled predicate to the pipeline,
// updates file-blocking state, and invalidates the scan cache. This is
// called by the dashboard when the user toggles detection rules.
func (c *Coordinator) Reconfigure(enabled func(string) bool, blockedExtensions []string, contentPatterns bool) {
	c.pipeline.Reconfigure(enabled)
	c.fb.Reconfigure(blockedExtensions, contentPatterns)
	c.cache.Invalidate()
}
