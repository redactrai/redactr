package rules

import (
	"reflect"
	"sort"
	"testing"
)

func TestFileBlockExtensionsAllOnNoExtras(t *testing.T) {
	eff := Effective(nil) // tier 1 file_block_* all true by default
	exts, contentPatterns := FileBlockExtensions(nil, eff, true)
	got := append([]string(nil), exts...)
	sort.Strings(got)
	want := []string{".env", ".key", ".p12", ".pem", ".pfx", ".tfstate"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("default extensions: got %v want %v", got, want)
	}
	if !contentPatterns {
		t.Error("contentPatterns should be true when both rule and config are true")
	}
}

func TestFileBlockExtensionsRuleDisabled(t *testing.T) {
	eff := Effective(map[string]bool{"file_block_env": false})
	exts, _ := FileBlockExtensions(nil, eff, true)
	for _, e := range exts {
		if e == ".env" {
			t.Error(".env should be excluded when file_block_env=false")
		}
	}
}

func TestFileBlockExtensionsContentPatternsAndLogic(t *testing.T) {
	eff := Effective(map[string]bool{"file_block_content_patterns": false})
	_, cp := FileBlockExtensions(nil, eff, true)
	if cp {
		t.Error("contentPatterns should be false when rule=false even if config=true")
	}
	eff2 := Effective(nil)
	_, cp2 := FileBlockExtensions(nil, eff2, false)
	if cp2 {
		t.Error("contentPatterns should be false when config=false even if rule=true")
	}
	eff3 := Effective(nil)
	_, cp3 := FileBlockExtensions(nil, eff3, true)
	if !cp3 {
		t.Error("contentPatterns should be true when both rule=true and config=true")
	}
}

func TestFileBlockExtensionsUserExtras(t *testing.T) {
	eff := Effective(nil)
	user := []string{".env", ".custom", ".PEM"} // .env and .pem are defaults; .custom is extra
	exts, _ := FileBlockExtensions(user, eff, true)
	hasCustom := false
	envCount := 0
	pemCount := 0
	for _, e := range exts {
		if e == ".custom" {
			hasCustom = true
		}
		if e == ".env" {
			envCount++
		}
		if e == ".pem" {
			pemCount++
		}
	}
	if !hasCustom {
		t.Error(".custom should be included as a user extra")
	}
	if envCount != 1 || pemCount != 1 {
		t.Errorf("default extensions should appear exactly once, got envCount=%d pemCount=%d", envCount, pemCount)
	}
}

func TestFileBlockExtensionsUserExtrasCaseInsensitive(t *testing.T) {
	// User wrote ".PEM" (uppercase). Should NOT be added as an extra,
	// because it lowercases to ".pem" which is already in the default set.
	eff := Effective(nil)
	exts, _ := FileBlockExtensions([]string{".PEM"}, eff, true)
	pemCount := 0
	for _, e := range exts {
		if e == ".PEM" {
			t.Error(".PEM should not appear as a duplicate; it matches default .pem case-insensitively")
		}
		if e == ".pem" {
			pemCount++
		}
	}
	if pemCount != 1 {
		t.Errorf(".pem should appear exactly once, got %d", pemCount)
	}
}
