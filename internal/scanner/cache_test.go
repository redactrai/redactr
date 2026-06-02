package scanner

import (
	"testing"
)

func TestCacheHitMiss(t *testing.T) {
	c := NewCache(100)

	result := &PipelineReport{
		Findings: []Finding{{Label: "EMAIL", Value: "a@b.com"}},
		TotalMs:  5,
	}

	c.Put("hello user@test.com", "redacted-text", result)

	text, report, hit := c.Get("hello user@test.com")
	if !hit {
		t.Fatal("expected cache hit")
	}
	if text != "redacted-text" {
		t.Errorf("expected redacted text, got %q", text)
	}
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(report.Findings))
	}

	_, _, hit = c.Get("different text")
	if hit {
		t.Error("expected cache miss")
	}
}

func TestCacheEviction(t *testing.T) {
	c := NewCache(2)

	c.Put("text1", "r1", &PipelineReport{})
	c.Put("text2", "r2", &PipelineReport{})
	c.Put("text3", "r3", &PipelineReport{})

	_, _, hit := c.Get("text1")
	if hit {
		t.Error("expected text1 evicted")
	}

	_, _, hit = c.Get("text3")
	if !hit {
		t.Error("expected text3 in cache")
	}
}

func TestCacheInvalidate(t *testing.T) {
	c := NewCache(100)
	c.Put("text1", "r1", &PipelineReport{})

	c.Invalidate()

	_, _, hit := c.Get("text1")
	if hit {
		t.Error("expected cache empty after invalidate")
	}
}

func TestCacheStats(t *testing.T) {
	c := NewCache(100)
	c.Put("text1", "r1", &PipelineReport{})

	c.Get("text1")
	c.Get("text1")
	c.Get("miss")

	stats := c.Stats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
	if stats.Size != 1 {
		t.Errorf("expected size 1, got %d", stats.Size)
	}
}
