package rules

import (
	"strings"
	"testing"
)

func TestCatalogTotals(t *testing.T) {
	rules := AllRules()
	groups := AllGroups()
	if len(rules) != 85 {
		t.Errorf("expected 85 rules, got %d", len(rules))
	}
	if len(groups) != 37 {
		t.Errorf("expected 37 groups, got %d", len(groups))
	}
}

func TestRuleIDsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, r := range AllRules() {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestGroupIDsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, g := range AllGroups() {
		if seen[g.ID] {
			t.Errorf("duplicate group id %q", g.ID)
		}
		seen[g.ID] = true
	}
}

func TestEveryRuleHasPopulatedFields(t *testing.T) {
	for _, r := range AllRules() {
		if r.ID == "" || r.Label == "" || r.Group == "" || r.Layer == "" {
			t.Errorf("rule %+v has empty required field", r)
		}
		if r.Tier == TierUnknown {
			t.Errorf("rule %q has TierUnknown", r.ID)
		}
		if r.ID != strings.ToLower(r.ID) {
			t.Errorf("rule id %q must be lowercase", r.ID)
		}
	}
}

func TestEveryRuleBelongsToKnownGroup(t *testing.T) {
	groups := make(map[string]GroupSpec)
	for _, g := range AllGroups() {
		groups[g.ID] = g
	}
	for _, r := range AllRules() {
		g, ok := groups[r.Group]
		if !ok {
			t.Errorf("rule %q references unknown group %q", r.ID, r.Group)
			continue
		}
		if g.Tier != r.Tier {
			t.Errorf("rule %q tier %v != group %q tier %v", r.ID, r.Tier, g.ID, g.Tier)
		}
	}
}

func TestEveryGroupReferencesKnownRules(t *testing.T) {
	rules := make(map[string]bool)
	for _, r := range AllRules() {
		rules[r.ID] = true
	}
	for _, g := range AllGroups() {
		if len(g.Rules) == 0 {
			t.Errorf("group %q has no rules", g.ID)
		}
		for _, id := range g.Rules {
			if !rules[id] {
				t.Errorf("group %q references unknown rule %q", g.ID, id)
			}
		}
	}
}

func TestTierCounts(t *testing.T) {
	counts := map[Tier]int{}
	for _, r := range AllRules() {
		counts[r.Tier]++
	}
	if counts[TierAlwaysOn] != 24 {
		t.Errorf("Tier 1 expected 24 rules, got %d", counts[TierAlwaysOn])
	}
	if counts[TierGoodToHave] != 33 {
		t.Errorf("Tier 2 expected 33 rules, got %d", counts[TierGoodToHave])
	}
	if counts[TierToBeSafer] != 28 {
		t.Errorf("Tier 3 expected 28 rules, got %d", counts[TierToBeSafer])
	}
}

func TestIsKnown(t *testing.T) {
	// Note: until catalog.go lands in Task 3, no rule will be known.
	// For now we only assert the negative case.
	if IsKnown("definitely_not_a_real_rule_id") {
		t.Error("nonsense rule id should not be known")
	}
}

func TestEffectiveAppliesDefaults(t *testing.T) {
	set := Effective(nil)
	if !set["aws_access_key"] {
		t.Error("Tier 1 rule should default to enabled")
	}
	if !set["email_regex"] {
		t.Error("Tier 2 rule should default to enabled")
	}
	if set["ipv4"] {
		t.Error("Tier 3 rule should default to disabled")
	}
}

func TestEffectiveRespectsOverrides(t *testing.T) {
	set := Effective(map[string]bool{
		"aws_access_key": false,
		"ipv4":           true,
	})
	if set["aws_access_key"] {
		t.Error("explicit false should override tier default")
	}
	if !set["ipv4"] {
		t.Error("explicit true should override tier default")
	}
}

func TestEffectiveIgnoresUnknownKeys(t *testing.T) {
	set := Effective(map[string]bool{"definitely_not_a_rule": true})
	if _, ok := set["definitely_not_a_rule"]; ok {
		t.Error("Effective should not propagate unknown keys")
	}
}

func TestEffectiveCoversAllRules(t *testing.T) {
	set := Effective(nil)
	if len(set) != len(AllRules()) {
		t.Errorf("Effective(nil) should cover every rule; got %d, want %d", len(set), len(AllRules()))
	}
}

func TestNormaliseStripsDefaults(t *testing.T) {
	in := map[string]bool{
		"aws_access_key": true,  // == default true, should be stripped
		"ipv4":           false, // == default false, should be stripped
		"email_regex":    false, // != default true, kept
	}
	out := Normalise(in)
	if _, ok := out["aws_access_key"]; ok {
		t.Error("default-matching key should be stripped")
	}
	if _, ok := out["ipv4"]; ok {
		t.Error("default-matching key should be stripped")
	}
	if v, ok := out["email_regex"]; !ok || v {
		t.Errorf("non-default key should be kept; got ok=%v v=%v", ok, v)
	}
}

func TestNormaliseDropsUnknown(t *testing.T) {
	out := Normalise(map[string]bool{"nope": true, "still_nope": false})
	if out != nil {
		t.Errorf("Normalise of all-unknown map should be nil; got %v", out)
	}
}

func TestNormaliseReturnsNilForEmpty(t *testing.T) {
	if Normalise(nil) != nil {
		t.Error("Normalise(nil) should be nil")
	}
	if Normalise(map[string]bool{}) != nil {
		t.Error("Normalise(empty) should be nil")
	}
}
