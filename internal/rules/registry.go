package rules

// AllRules returns the complete catalogue of detection rules.
// The catalogue is populated by init() blocks in catalog.go.
func AllRules() []RuleSpec { return catalog }

// AllGroups returns the complete list of rule groups.
func AllGroups() []GroupSpec { return groups }

// IsKnown reports whether a rule ID exists in the catalogue.
func IsKnown(id string) bool {
	_, ok := ruleByID[id]
	return ok
}

// ByID returns the RuleSpec for a given rule ID. The bool indicates
// whether the lookup succeeded.
func ByID(id string) (RuleSpec, bool) {
	r, ok := ruleByID[id]
	return r, ok
}

// catalog and groups are populated by init() blocks in catalog.go.
// ruleByID is built lazily on first access via the package init below.
var (
	catalog  []RuleSpec
	groups   []GroupSpec
	ruleByID map[string]RuleSpec
)

// init builds the rule-id index. catalog/groups may be empty here if no
// catalog data has been registered yet (this is intentional during
// incremental development).
func init() {
	ruleByID = make(map[string]RuleSpec, len(catalog))
	for _, r := range catalog {
		ruleByID[r.ID] = r
	}
}

// Effective returns a fully-resolved enabled-set for every rule in the
// catalogue. Unknown keys in user are ignored. Missing rules fall back
// to their tier's default (Tier 1 + 2 default true, Tier 3 default false).
func Effective(user map[string]bool) map[string]bool {
	out := make(map[string]bool, len(catalog))
	for _, r := range catalog {
		if v, ok := user[r.ID]; ok {
			out[r.ID] = v
		} else {
			out[r.ID] = ResolveDefault(r.Tier)
		}
	}
	return out
}

// Normalise drops any user entry whose value equals the rule's tier
// default, and drops unknown keys. Returns nil if the result would be
// empty (so callers can store nil instead of a zero-length map).
func Normalise(user map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for id, v := range user {
		r, ok := ruleByID[id]
		if !ok {
			continue
		}
		if v == ResolveDefault(r.Tier) {
			continue
		}
		out[id] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
