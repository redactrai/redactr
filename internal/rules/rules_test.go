package rules

import "testing"

func TestTierConstants(t *testing.T) {
	if TierAlwaysOn == TierGoodToHave || TierGoodToHave == TierToBeSafer || TierAlwaysOn == TierToBeSafer {
		t.Fatal("tier constants must be distinct")
	}
	if !ResolveDefault(TierAlwaysOn) || !ResolveDefault(TierGoodToHave) {
		t.Fatal("tiers 1 and 2 must default to enabled")
	}
	if ResolveDefault(TierToBeSafer) {
		t.Fatal("tier 3 must default to disabled")
	}
}

func TestTierString(t *testing.T) {
	cases := map[Tier]string{
		TierAlwaysOn:   "always_on",
		TierGoodToHave: "good_to_have",
		TierToBeSafer:  "to_be_safer",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Errorf("Tier(%d).String() = %q, want %q", tier, got, want)
		}
	}
}
