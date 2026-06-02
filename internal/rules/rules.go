// Package rules holds the canonical catalogue of detection rules and
// groups, plus utilities to resolve defaults and effective state.
package rules

type Tier int

const (
	TierUnknown Tier = iota
	TierAlwaysOn
	TierGoodToHave
	TierToBeSafer
)

func (t Tier) String() string {
	switch t {
	case TierAlwaysOn:
		return "always_on"
	case TierGoodToHave:
		return "good_to_have"
	case TierToBeSafer:
		return "to_be_safer"
	}
	return "unknown"
}

// RuleSpec describes a single detection rule.
type RuleSpec struct {
	ID       string // stable config key, e.g. "aws_access_key"
	Label    string // human label for the UI
	Describe string // one-line description
	Group    string // group ID
	Tier     Tier
	Layer    string // "presidio" | "entropy" | "gliner" | "fileblock"
}

// GroupSpec describes a UI group of rules.
type GroupSpec struct {
	ID    string
	Label string
	Tier  Tier
	Rules []string // ordered rule IDs
}

// ResolveDefault returns the default enabled state for a rule whose tier is t.
func ResolveDefault(t Tier) bool {
	return t == TierAlwaysOn || t == TierGoodToHave
}
