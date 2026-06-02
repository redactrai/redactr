package fileblock

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
)

var contentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^[A-Z_]+=.+$`),
}

const contentThreshold = 3

type fileblockState struct {
	extensions      map[string]bool
	contentPatterns bool
}

type Blocker struct {
	state atomic.Pointer[fileblockState]
}

func New(extensions []string, contentPatterns bool) *Blocker {
	b := &Blocker{}
	b.replaceState(extensions, contentPatterns)
	return b
}

func (b *Blocker) replaceState(extensions []string, cp bool) {
	ext := make(map[string]bool, len(extensions))
	for _, e := range extensions {
		ext[strings.ToLower(e)] = true
	}
	b.state.Store(&fileblockState{
		extensions:      ext,
		contentPatterns: cp,
	})
}

func (b *Blocker) IsBlockedFile(path string) bool {
	state := b.state.Load()
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	if state.extensions[ext] {
		return true
	}
	if state.extensions["."+base] || state.extensions[base] {
		return true
	}
	return false
}

func (b *Blocker) IsBlockedContent(content string) bool {
	state := b.state.Load()
	if !state.contentPatterns {
		return false
	}
	for _, pattern := range contentPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) >= contentThreshold {
			return true
		}
	}
	return false
}

func (b *Blocker) RedactionLabel(path string) string {
	ext := filepath.Ext(path)
	base := filepath.Base(path)
	return fmt.Sprintf("[REDACTED-FILE-%s: %s]", ext, base)
}

func (b *Blocker) SetExtensions(extensions []string) {
	cur := b.state.Load()
	b.replaceState(extensions, cur.contentPatterns)
}

// Reconfigure replaces the blocked-extension set and the content-patterns
// flag in a single atomic update.
func (b *Blocker) Reconfigure(extensions []string, contentPatterns bool) {
	b.replaceState(extensions, contentPatterns)
}
