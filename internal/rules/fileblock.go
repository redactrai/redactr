package rules

import "strings"

// FileBlockExtensions derives the file-extension list and content-patterns
// flag passed to the fileblock layer, from a per-rule effective map plus
// any user-defined extra extensions.
//
//   - userExtensions: caller's `cfg.FileBlocking.BlockedExtensions`. Any
//     entry that, when lowercased, isn't already in the default-six set
//     is appended verbatim (preserving the user's casing).
//   - eff: a fully-resolved enabled-set, e.g. from Effective().
//   - contentPatternsConfig: caller's `cfg.FileBlocking.ContentPatternsEnabled`.
//
// The returned content-patterns flag is the AND of the rule toggle and
// the legacy config flag — disabling either kills it.
func FileBlockExtensions(userExtensions []string, eff map[string]bool, contentPatternsConfig bool) ([]string, bool) {
	defaults := []struct{ id, ext string }{
		{"file_block_env", ".env"},
		{"file_block_tfstate", ".tfstate"},
		{"file_block_pem", ".pem"},
		{"file_block_key", ".key"},
		{"file_block_p12", ".p12"},
		{"file_block_pfx", ".pfx"},
	}
	var out []string
	defaultSet := make(map[string]bool, len(defaults))
	for _, d := range defaults {
		defaultSet[d.ext] = true
		if eff[d.id] {
			out = append(out, d.ext)
		}
	}
	for _, e := range userExtensions {
		if !defaultSet[strings.ToLower(e)] {
			out = append(out, e)
		}
	}
	return out, contentPatternsConfig && eff["file_block_content_patterns"]
}
