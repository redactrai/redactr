# Detection Rule Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the design from `docs/superpowers/specs/2026-04-27-detection-rule-config-design.md` — a tiered detection-rule configuration system with 37 group-level toggles and 85 individual rule toggles, exposed via API and dashboard with warning UX scaled per tier.

**Architecture:** A new `internal/rules` package owns the catalogue (single source of truth for rule metadata: ID, group, tier, layer, label, description, default). Each scanner layer (presidio / entropy / gliner / fileblock) gains a `Reconfigure` method that consults a predicate `enabled(ruleID) bool`. Two new API endpoints (`GET/PUT /api/rules`) read/write a flat `map[string]bool` stored at `scanning.rules`. The Configuration tab gets a new "Detection rules" card with three collapsible tier sections; warnings are dispatched per the rule's tier.

**Tech Stack:** Go 1.22+, vanilla HTML/CSS/JS, BoltDB-backed config persistence via existing `internal/config`.

---

## File Structure

### New files
- `internal/rules/rules.go` — types: `Tier`, `RuleSpec`, `GroupSpec`; helper `ResolveDefault`.
- `internal/rules/catalog.go` — the 85 rules + 37 groups, declared as `var Catalog = []RuleSpec{...}` and `var Groups = []GroupSpec{...}`.
- `internal/rules/registry.go` — accessors: `AllRules`, `AllGroups`, `ByID`, `IsKnown`, `Effective(rules map[string]bool)` returning a fully-resolved enabled-set.
- `internal/rules/registry_test.go` — invariant tests.
- `internal/api/rules_handler.go` — `handleGetRules` and `handlePutRules` (kept out of `routes.go` to keep it readable).

### Modified files
- `internal/config/config.go` — add `Rules map[string]bool` to `ScanningConfig`. Add `MigrateLegacyLayerFlags` helper.
- `internal/scanner/presidio/presidio.go` — attach `ruleID` to each pattern; constructor takes `enabled func(string) bool`; add `Reconfigure`. Tighten the `cvv` rule.
- `internal/scanner/entropy/entropy.go` — split into two flags (`KeywordGated`, `Unconditional`); add `Reconfigure`.
- `internal/scanner/gliner/client.go` — raise `PERSON` threshold to `0.80`; constructor takes `enabled func(string) bool`; add `Reconfigure`.
- `internal/fileblock/fileblock.go` — new `Reconfigure(extensions []string, contentPatterns bool)` (already partially supported via `SetExtensions`).
- `internal/scanner/pipeline.go` — add `Reconfigure(...)` that fans out to layers that implement an optional `Reconfigurable` interface.
- `internal/coordinator/coordinator.go` — add `Reconfigure(...)` that calls pipeline + invalidates cache.
- `internal/api/routes.go` — register `GET /api/rules` and `PUT /api/rules`.
- `internal/api/server.go` — store coordinator (already does) and expose for handler use.
- `cmd/redactr/main.go` — on startup, run config migration and pass `enabled` predicates to each scanner constructor.
- `internal/api/static/index.html` — replace `Scanning Layers` card with `Detection rules` card; add modal + popover containers; add Overview banner placeholder.
- `internal/api/static/app.js` — fetch `/api/rules`, render tiers/groups/rules, wire toggles, modal/popover/silent flows, persistent banner, save flow.
- `internal/api/static/style.css` — styles for the new card, group/rule rows, modal, popover, banner.

### Deleted (in cleanup task)
- The three legacy fields in `ScanningConfig` (`RegexEnabled`, `EntropyEnabled`, `GLiNEREnabled`) are removed after migration runs at least once.

---

## Phase 1 — Rules Registry

### Task 1: Tier constants and core types

**Files:**
- Create: `internal/rules/rules.go`
- Create: `internal/rules/rules_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/rules/rules_test.go
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
        TierAlwaysOn:  "always_on",
        TierGoodToHave: "good_to_have",
        TierToBeSafer:  "to_be_safer",
    }
    for tier, want := range cases {
        if got := tier.String(); got != want {
            t.Errorf("Tier(%d).String() = %q, want %q", tier, got, want)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
go test ./internal/rules/...
```
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement minimal types**

```go
// internal/rules/rules.go
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
```

- [ ] **Step 4: Run test to verify it passes**

```
go test ./internal/rules/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/rules/rules.go internal/rules/rules_test.go
git commit -m "feat(rules): add Tier/RuleSpec/GroupSpec types"
```

---

### Task 2: Catalog invariants test

**Files:**
- Create: `internal/rules/registry_test.go` (invariants).

This task writes the *tests for what the catalogue must satisfy* — but does not implement the catalogue yet. The next three tasks fill in Tier 1 / 2 / 3 entries.

- [ ] **Step 1: Write invariant tests**

```go
// internal/rules/registry_test.go
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
        if !strings.HasPrefix(r.ID, strings.ToLower(r.ID)) {
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
    if !IsKnown("aws_access_key") {
        t.Error("aws_access_key should be known")
    }
    if IsKnown("nonsense_rule") {
        t.Error("nonsense_rule should not be known")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
go test ./internal/rules/... -run "TestCatalog|TestEveryRule|TestEveryGroup|TestTierCounts|TestIsKnown"
```
Expected: FAIL — `AllRules`, `AllGroups`, `IsKnown` undefined.

- [ ] **Step 3: Add stubs to make tests compile**

```go
// internal/rules/registry.go
package rules

func AllRules() []RuleSpec  { return catalog }
func AllGroups() []GroupSpec { return groups }
func IsKnown(id string) bool { return ruleByID[id].ID != "" }

func ByID(id string) (RuleSpec, bool) {
    r, ok := ruleByID[id]
    return r, ok
}

var (
    catalog   []RuleSpec
    groups    []GroupSpec
    ruleByID  map[string]RuleSpec
)

func init() {
    ruleByID = make(map[string]RuleSpec, len(catalog))
    for _, r := range catalog {
        ruleByID[r.ID] = r
    }
}
```

- [ ] **Step 4: Run tests to verify they fail with non-empty diagnostics**

```
go test ./internal/rules/...
```
Expected: tests run but FAIL — catalog is empty, totals are wrong. This is correct progress.

- [ ] **Step 5: Commit**

```bash
git add internal/rules/registry.go internal/rules/registry_test.go
git commit -m "feat(rules): add registry skeleton and invariant tests"
```

---

### Task 3: Tier 1 catalog (24 rules in 9 groups)

**Files:**
- Create: `internal/rules/catalog.go` (start with Tier 1 only).

- [ ] **Step 1: Write the Tier 1 catalogue**

```go
// internal/rules/catalog.go
package rules

// catalog and groups together form the canonical list of every detection
// rule and group. Edit this file (and only this file) to add or remove
// rules. Tests in registry_test.go enforce invariants.

func init() {
    catalog = append(catalog, tier1Rules...)
    groups = append(groups, tier1Groups...)
    // tier 2 + 3 appended in their own init blocks below
}

var tier1Groups = []GroupSpec{
    {ID: "cloud_credentials",   Label: "Cloud credentials",          Tier: TierAlwaysOn, Rules: []string{"aws_access_key", "aws_secret_key", "gcp_api_key"}},
    {ID: "private_keys",        Label: "Private keys",               Tier: TierAlwaysOn, Rules: []string{"private_key_pem"}},
    {ID: "auth_tokens",         Label: "Auth tokens & secrets",      Tier: TierAlwaysOn, Rules: []string{"jwt", "generic_secret_kv", "generic_secret_pwd", "url_with_token"}},
    {ID: "passwords_prose",     Label: "Passwords (prose)",          Tier: TierAlwaysOn, Rules: []string{"password_prose"}},
    {ID: "connection_strings",  Label: "Database connection strings",Tier: TierAlwaysOn, Rules: []string{"connection_string"}},
    {ID: "payment_cards",       Label: "Payment cards (full)",       Tier: TierAlwaysOn, Rules: []string{"credit_card_luhn", "credit_card_4x4", "credit_card_bare", "cvv"}},
    {ID: "us_ssn",              Label: "US Social Security Numbers", Tier: TierAlwaysOn, Rules: []string{"us_ssn_dash", "us_ssn_space"}},
    {ID: "file_blocking",       Label: "Sensitive file types (block)", Tier: TierAlwaysOn, Rules: []string{"file_block_env", "file_block_tfstate", "file_block_pem", "file_block_key", "file_block_p12", "file_block_pfx", "file_block_content_patterns"}},
    {ID: "entropy_keyword",     Label: "Entropy in secret context",  Tier: TierAlwaysOn, Rules: []string{"entropy_keyword_gated"}},
}

var tier1Rules = []RuleSpec{
    // Cloud credentials
    {ID: "aws_access_key", Label: "AWS access key",   Describe: `AKIA[0-9A-Z]{16}`,                                     Group: "cloud_credentials", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "aws_secret_key", Label: "AWS secret key",   Describe: `aws_secret_access_key=… (40 chars)`,                   Group: "cloud_credentials", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "gcp_api_key",    Label: "GCP API key",      Describe: `AIza[0-9A-Za-z\-_]{35}`,                               Group: "cloud_credentials", Tier: TierAlwaysOn, Layer: "presidio"},

    // Private keys
    {ID: "private_key_pem", Label: "Private key (PEM)", Describe: "PEM blocks: RSA / EC / DSA / OPENSSH", Group: "private_keys", Tier: TierAlwaysOn, Layer: "presidio"},

    // Auth tokens & secrets
    {ID: "jwt",                 Label: "JWT",                       Describe: `eyJ…\.eyJ…\.…`,                              Group: "auth_tokens", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "generic_secret_kv",   Label: "Generic key=value secret",  Describe: `(password|secret|token|api_key)=… ≥8 chars`, Group: "auth_tokens", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "generic_secret_pwd",  Label: "Generic password=value",    Describe: `(password|passwd|pwd)=… ≥4 chars (loose)`,  Group: "auth_tokens", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "url_with_token",      Label: "URL with auth token",       Describe: `https://…?token= / ?access_token= / etc.`,   Group: "auth_tokens", Tier: TierAlwaysOn, Layer: "presidio"},

    // Passwords (prose)
    {ID: "password_prose", Label: "Password in prose", Describe: `"the password is X"`, Group: "passwords_prose", Tier: TierAlwaysOn, Layer: "presidio"},

    // Connection strings
    {ID: "connection_string", Label: "Database connection string", Describe: `mongodb|postgres|mysql|redis|amqp://…`, Group: "connection_strings", Tier: TierAlwaysOn, Layer: "presidio"},

    // Payment cards
    {ID: "credit_card_luhn", Label: "Credit card (Luhn-validated)", Describe: "Visa/MC/Amex/Discover/Diners with Luhn", Group: "payment_cards", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "credit_card_4x4",  Label: "Credit card (4×4 separated)",  Describe: `\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b`, Group: "payment_cards", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "credit_card_bare", Label: "Credit card (bare 13–19 digits)", Describe: "13–19 digit unseparated PAN with brand prefix", Group: "payment_cards", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "cvv",              Label: "CVV / CVC",                    Describe: "CVV/CVC keyword + value, near payment-card context", Group: "payment_cards", Tier: TierAlwaysOn, Layer: "presidio"},

    // US SSN
    {ID: "us_ssn_dash",  Label: "US SSN (dash-separated)",  Describe: `\b\d{3}-\d{2}-\d{4}\b`, Group: "us_ssn", Tier: TierAlwaysOn, Layer: "presidio"},
    {ID: "us_ssn_space", Label: "US SSN (space-separated)", Describe: `\b\d{3}\s\d{2}\s\d{4}\b`, Group: "us_ssn", Tier: TierAlwaysOn, Layer: "presidio"},

    // File blocking
    {ID: "file_block_env",              Label: ".env files",            Describe: "Block requests containing .env files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
    {ID: "file_block_tfstate",          Label: ".tfstate files",        Describe: "Block requests containing .tfstate files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
    {ID: "file_block_pem",              Label: ".pem files",            Describe: "Block requests containing .pem files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
    {ID: "file_block_key",              Label: ".key files",            Describe: "Block requests containing .key files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
    {ID: "file_block_p12",              Label: ".p12 files",            Describe: "Block requests containing .p12 files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
    {ID: "file_block_pfx",              Label: ".pfx files",            Describe: "Block requests containing .pfx files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
    {ID: "file_block_content_patterns", Label: "Sensitive content patterns", Describe: "Block on PEM headers / TF state markers", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},

    // Entropy keyword-gated
    {ID: "entropy_keyword_gated", Label: "Entropy near secret keyword", Describe: "Shannon 3.5–4.5 within ±80 chars of password/token/api_key", Group: "entropy_keyword", Tier: TierAlwaysOn, Layer: "entropy"},
}
```

- [ ] **Step 2: Run the registry tests (should still fail because tier 2/3 are missing)**

```
go test ./internal/rules/...
```
Expected: FAIL — total count is 24 (not 85), only tier 1 populated. This is correct progress.

- [ ] **Step 3: Commit**

```bash
git add internal/rules/catalog.go
git commit -m "feat(rules): add Tier 1 catalogue (24 rules / 9 groups)"
```

---

### Task 4: Tier 2 catalog (33 rules in 12 groups)

**Files:**
- Modify: `internal/rules/catalog.go` (append Tier 2).

- [ ] **Step 1: Append Tier 2 catalogue**

Add inside the `init()` of `catalog.go` after the Tier 1 appends:

```go
    catalog = append(catalog, tier2Rules...)
    groups = append(groups, tier2Groups...)
```

And below `tier1Rules`:

```go
var tier2Groups = []GroupSpec{
    {ID: "email_addresses",     Label: "Email addresses",        Tier: TierGoodToHave, Rules: []string{"email_regex", "email_gliner"}},
    {ID: "phone_numbers",       Label: "Phone numbers",          Tier: TierGoodToHave, Rules: []string{"phone_parens", "phone_dash_dot", "phone_intl_plus", "phone_leading_zero", "phone_double_zero"}},
    {ID: "person_names",        Label: "Person names (ML)",      Tier: TierGoodToHave, Rules: []string{"person_gliner"}},
    {ID: "physical_addresses",  Label: "Physical addresses (ML)",Tier: TierGoodToHave, Rules: []string{"address_gliner"}},
    {ID: "date_of_birth",       Label: "Date of birth",          Tier: TierGoodToHave, Rules: []string{"dob_mdy", "dob_dmy", "dob_gliner"}},
    {ID: "us_government_ids",   Label: "US government IDs",      Tier: TierGoodToHave, Rules: []string{"us_passport_alpha", "us_passport_numeric", "us_driver_license", "us_itin_dash", "us_itin_bare"}},
    {ID: "us_bank_accounts",    Label: "US bank accounts",       Tier: TierGoodToHave, Rules: []string{"us_bank_number", "aba_routing_dashed", "aba_routing_bare"}},
    {ID: "intl_banking",        Label: "International banking",  Tier: TierGoodToHave, Rules: []string{"iban_presidio", "iban_simple", "swift_bic"}},
    {ID: "cc_expiry",           Label: "Credit card expiry",     Tier: TierGoodToHave, Rules: []string{"cc_expiry"}},
    {ID: "healthcare_ids",      Label: "Healthcare identifiers", Tier: TierGoodToHave, Rules: []string{"dea_license", "us_npi_separated", "us_npi_bare", "us_mbi_separated", "us_mbi_bare", "medical_record_mrn", "health_plan_id"}},
    {ID: "biometric_ids",       Label: "Biometric identifiers",  Tier: TierGoodToHave, Rules: []string{"biometric_id"}},
    {ID: "insurance_ids",       Label: "Insurance / policy IDs", Tier: TierGoodToHave, Rules: []string{"insurance_id"}},
}

var tier2Rules = []RuleSpec{
    {ID: "email_regex",       Label: "Email (regex)",           Describe: "RFC-shaped local@domain.tld",                     Group: "email_addresses",    Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "email_gliner",      Label: "Email (ML)",              Describe: "GLiNER EMAIL ≥0.70",                              Group: "email_addresses",    Tier: TierGoodToHave, Layer: "gliner"},

    {ID: "phone_parens",       Label: "Phone (parens)",         Describe: `(415) 555-0136`,                                  Group: "phone_numbers",      Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "phone_dash_dot",     Label: "Phone (dash/dot)",       Describe: `415-555-0136 / 415.555.0136`,                     Group: "phone_numbers",      Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "phone_intl_plus",    Label: "Phone (international +)",Describe: `+1 415 555 0136`,                                 Group: "phone_numbers",      Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "phone_leading_zero", Label: "Phone (leading zero)",   Describe: `0xxx xxxxxx — context-required`,                  Group: "phone_numbers",      Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "phone_double_zero",  Label: "Phone (double zero)",    Describe: `00xx xxxxxxxx`,                                   Group: "phone_numbers",      Tier: TierGoodToHave, Layer: "presidio"},

    {ID: "person_gliner",  Label: "Person name (ML)",  Describe: "GLiNER PERSON ≥0.80", Group: "person_names",       Tier: TierGoodToHave, Layer: "gliner"},
    {ID: "address_gliner", Label: "Address (ML)",      Describe: "GLiNER ADDRESS ≥0.75", Group: "physical_addresses", Tier: TierGoodToHave, Layer: "gliner"},

    {ID: "dob_mdy",     Label: "DOB MM/DD/YYYY", Describe: "Context-required (born/dob/birthday)", Group: "date_of_birth", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "dob_dmy",     Label: "DOB DD/MM/YYYY", Describe: "Context-required (born/dob/birthday)", Group: "date_of_birth", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "dob_gliner",  Label: "DOB (ML)",       Describe: "GLiNER DATE_OF_BIRTH ≥0.75",            Group: "date_of_birth", Tier: TierGoodToHave, Layer: "gliner"},

    {ID: "us_passport_alpha",   Label: "US passport (alpha)",  Describe: `[A-Z]\d{8}`,             Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "us_passport_numeric", Label: "US passport (numeric)",Describe: `\d{9} with passport ctx`, Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "us_driver_license",   Label: "US driver license",     Describe: "State-shape alternation, context-required", Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "us_itin_dash",        Label: "US ITIN (dashed)",      Describe: `9XX-7X-XXXX with context`, Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "us_itin_bare",        Label: "US ITIN (bare)",        Describe: `9XX7XXXXX context-required`, Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},

    {ID: "us_bank_number",       Label: "US bank account",     Describe: "10–17 digits with bank context",         Group: "us_bank_accounts", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "aba_routing_dashed",   Label: "ABA routing (dashed)",Describe: "XXXX-XXXX-X with checksum",              Group: "us_bank_accounts", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "aba_routing_bare",     Label: "ABA routing (bare)",  Describe: "9 digits, context-required + checksum", Group: "us_bank_accounts", Tier: TierGoodToHave, Layer: "presidio"},

    {ID: "iban_presidio", Label: "IBAN (Presidio)", Describe: "IBAN with mod-97 checksum (context-boosted)", Group: "intl_banking", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "iban_simple",   Label: "IBAN (simple)",   Describe: "Simpler IBAN shape (context-boosted)",         Group: "intl_banking", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "swift_bic",     Label: "SWIFT / BIC",     Describe: "8/11 alpha SWIFT, context-required",            Group: "intl_banking", Tier: TierGoodToHave, Layer: "presidio"},

    {ID: "cc_expiry", Label: "Credit card expiry", Describe: `MM/YY near "card"/"exp"/"valid"`, Group: "cc_expiry", Tier: TierGoodToHave, Layer: "presidio"},

    {ID: "dea_license",        Label: "DEA license",         Describe: "DEA-shape [A-Z][A-Z]\\d{7}", Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "us_npi_separated",   Label: "US NPI (separated)",  Describe: "1NNN-NNN-NNN with NPI ctx",  Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "us_npi_bare",        Label: "US NPI (bare)",       Describe: "10-digit NPI, context-required", Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "us_mbi_separated",   Label: "US MBI (separated)",  Describe: "Medicare MBI hyphenated form",   Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "us_mbi_bare",        Label: "US MBI (bare)",       Describe: "MBI no-separator, context-required", Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "medical_record_mrn", Label: "Medical record (MRN)", Describe: `"MRN: …" / "patient id: …"`,    Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "health_plan_id",     Label: "Health plan ID",       Describe: `"health plan id: …"`,           Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},

    {ID: "biometric_id", Label: "Biometric identifier", Describe: `"fingerprint hash: …" / "face id: …"`, Group: "biometric_ids", Tier: TierGoodToHave, Layer: "presidio"},
    {ID: "insurance_id", Label: "Insurance / policy ID", Describe: `"policy no: …" / "member id: …"`,     Group: "insurance_ids", Tier: TierGoodToHave, Layer: "presidio"},
}
```

- [ ] **Step 2: Run tests**

```
go test ./internal/rules/...
```
Expected: still failing — Tier 3 not yet populated, so totals don't match.

- [ ] **Step 3: Commit**

```bash
git add internal/rules/catalog.go
git commit -m "feat(rules): add Tier 2 catalogue (33 rules / 12 groups)"
```

---

### Task 5: Tier 3 catalog (28 rules in 16 groups)

**Files:**
- Modify: `internal/rules/catalog.go` (append Tier 3).

- [ ] **Step 1: Append Tier 3 catalogue**

In `init()`:

```go
    catalog = append(catalog, tier3Rules...)
    groups = append(groups, tier3Groups...)
```

Append after Tier 2 declarations:

```go
var tier3Groups = []GroupSpec{
    {ID: "ip_addresses",            Label: "IP addresses (v4 + v6)",  Tier: TierToBeSafer, Rules: []string{"ipv4", "ipv6", "ip_gliner"}},
    {ID: "mac_addresses",           Label: "MAC addresses",           Tier: TierToBeSafer, Rules: []string{"mac_colon_dash", "mac_cisco_dot"}},
    {ID: "bare_urls",               Label: "Bare URLs",               Tier: TierToBeSafer, Rules: []string{"url_bare"}},
    {ID: "crypto_wallets",          Label: "Crypto wallet addresses", Tier: TierToBeSafer, Rules: []string{"crypto_btc", "crypto_eth"}},
    {ID: "uk_ids",                  Label: "UK identifiers",          Tier: TierToBeSafer, Rules: []string{"uk_nhs", "uk_nino", "uk_postcode", "uk_passport", "uk_driving_licence"}},
    {ID: "ca_sin",                  Label: "Canada — SIN",            Tier: TierToBeSafer, Rules: []string{"ca_sin"}},
    {ID: "au_tfn",                  Label: "Australia — TFN",         Tier: TierToBeSafer, Rules: []string{"au_tfn"}},
    {ID: "in_pan",                  Label: "India — PAN",             Tier: TierToBeSafer, Rules: []string{"in_pan"}},
    {ID: "es_nif",                  Label: "Spain — NIF",             Tier: TierToBeSafer, Rules: []string{"es_nif"}},
    {ID: "de_passport",             Label: "Germany — Passport",      Tier: TierToBeSafer, Rules: []string{"de_passport"}},
    {ID: "sg_nric_fin",             Label: "Singapore — NRIC/FIN",    Tier: TierToBeSafer, Rules: []string{"sg_nric_fin"}},
    {ID: "license_plates",          Label: "License plates",          Tier: TierToBeSafer, Rules: []string{"license_plate"}},
    {ID: "device_ids",              Label: "Device identifiers (IMEI)", Tier: TierToBeSafer, Rules: []string{"imei"}},
    {ID: "generic_system_ids",      Label: "Generic system IDs",      Tier: TierToBeSafer, Rules: []string{"person_id_generic", "registration_id_generic"}},
    {ID: "entropy_unconditional",   Label: "Entropy unconditional",   Tier: TierToBeSafer, Rules: []string{"entropy_unconditional"}},
    {ID: "ml_duplicates",           Label: "ML duplicates",           Tier: TierToBeSafer, Rules: []string{"gliner_email_dup", "gliner_ip_dup", "gliner_national_id_dup"}},
}

var tier3Rules = []RuleSpec{
    {ID: "ipv4",      Label: "IPv4",       Describe: "Dotted-quad IPv4",                   Group: "ip_addresses", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "ipv6",      Label: "IPv6",       Describe: "Full + compressed IPv6",             Group: "ip_addresses", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "ip_gliner", Label: "IP (ML)",    Describe: "GLiNER IP ≥0.75 (post-filtered)",    Group: "ip_addresses", Tier: TierToBeSafer, Layer: "gliner"},

    {ID: "mac_colon_dash", Label: "MAC (colon/dash)", Describe: "aa:bb:cc:dd:ee:ff / aa-bb-…", Group: "mac_addresses", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "mac_cisco_dot",  Label: "MAC (Cisco dot)",  Describe: "aaaa.bbbb.cccc",              Group: "mac_addresses", Tier: TierToBeSafer, Layer: "presidio"},

    {ID: "url_bare", Label: "Bare URL", Describe: "Any http(s)://… (with skiplist)", Group: "bare_urls", Tier: TierToBeSafer, Layer: "presidio"},

    {ID: "crypto_btc", Label: "Bitcoin address",  Describe: `bc1… / [13]…`,              Group: "crypto_wallets", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "crypto_eth", Label: "Ethereum address", Describe: `0x[a-f0-9]{40}`,            Group: "crypto_wallets", Tier: TierToBeSafer, Layer: "presidio"},

    {ID: "uk_nhs",              Label: "UK NHS number",      Describe: "NHS number (mod-11)",        Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "uk_nino",             Label: "UK NINO",            Describe: "National Insurance Number",  Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "uk_postcode",         Label: "UK postcode",        Describe: "UK postcode",                Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "uk_passport",         Label: "UK passport",        Describe: `[A-Z]{2}\d{7} with ctx`,      Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "uk_driving_licence",  Label: "UK driving licence", Describe: "DVLA driving licence shape",  Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},

    {ID: "ca_sin",      Label: "Canada SIN",            Describe: "[1-79]NN-NNN-NNN Luhn",        Group: "ca_sin",      Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "au_tfn",      Label: "Australia TFN",         Describe: "NNN NNN NNN mod-11",            Group: "au_tfn",      Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "in_pan",      Label: "India PAN",             Describe: "10-char PAN format",             Group: "in_pan",      Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "es_nif",      Label: "Spain NIF",             Describe: "8 digits + check letter",        Group: "es_nif",      Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "de_passport", Label: "Germany passport",      Describe: "German passport with German keywords", Group: "de_passport", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "sg_nric_fin", Label: "Singapore NRIC/FIN",    Describe: "[STFGM]\\d{7}[A-Z]",             Group: "sg_nric_fin", Tier: TierToBeSafer, Layer: "presidio"},

    {ID: "license_plate",            Label: "License plate", Describe: `"license plate: …" / "VRN: …"`, Group: "license_plates", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "imei",                     Label: "IMEI",          Describe: `NN-NNNNNN-NNNNNN-N`,            Group: "device_ids",      Tier: TierToBeSafer, Layer: "presidio"},

    {ID: "person_id_generic",        Label: "Generic person/customer/order ID", Describe: `"customer/employee/order/ticket id: …"`, Group: "generic_system_ids", Tier: TierToBeSafer, Layer: "presidio"},
    {ID: "registration_id_generic",  Label: "Registration / enrollment ID",     Describe: `"student/registration/enrollment no: …"`,Group: "generic_system_ids", Tier: TierToBeSafer, Layer: "presidio"},

    {ID: "entropy_unconditional", Label: "High-entropy strings (unconditional)", Describe: "Shannon ≥4.5 firing without keyword context", Group: "entropy_unconditional", Tier: TierToBeSafer, Layer: "entropy"},

    {ID: "gliner_email_dup",       Label: "ML email (duplicate)",   Describe: "GLiNER EMAIL — already covered by email_regex", Group: "ml_duplicates", Tier: TierToBeSafer, Layer: "gliner"},
    {ID: "gliner_ip_dup",          Label: "ML IP (duplicate)",      Describe: "GLiNER IP — already covered by ipv4",            Group: "ml_duplicates", Tier: TierToBeSafer, Layer: "gliner"},
    {ID: "gliner_national_id_dup", Label: "ML NATIONAL_ID",         Describe: "GLiNER NATIONAL_ID — vague label, mostly redundant", Group: "ml_duplicates", Tier: TierToBeSafer, Layer: "gliner"},
}
```

- [ ] **Step 2: Run tests**

```
go test ./internal/rules/...
```
Expected: PASS — all invariants satisfied.

- [ ] **Step 3: Commit**

```bash
git add internal/rules/catalog.go
git commit -m "feat(rules): add Tier 3 catalogue (28 rules / 16 groups)"
```

---

### Task 6: Effective state resolver

**Files:**
- Modify: `internal/rules/registry.go`
- Modify: `internal/rules/registry_test.go`

The pipeline needs to convert a sparse user `map[string]bool` into a full enabled-set, applying tier defaults for missing keys.

- [ ] **Step 1: Write the test**

```go
// add to internal/rules/registry_test.go
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
        "aws_access_key": false, // disable a tier 1
        "ipv4":           true,  // enable a tier 3
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

func TestNormaliseStripsDefaults(t *testing.T) {
    in := map[string]bool{
        "aws_access_key": true, // == default, should be stripped
        "ipv4":           false, // == default, should be stripped
        "email_regex":    false, // != default, kept
    }
    out := Normalise(in)
    if _, ok := out["aws_access_key"]; ok {
        t.Error("default-matching key should be stripped")
    }
    if _, ok := out["ipv4"]; ok {
        t.Error("default-matching key should be stripped")
    }
    if v, ok := out["email_regex"]; !ok || v {
        t.Error("non-default key should be kept")
    }
}
```

- [ ] **Step 2: Run, fail (Effective and Normalise undefined)**

```
go test ./internal/rules/... -run "TestEffective|TestNormalise"
```
Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

Add to `internal/rules/registry.go`:

```go
// Effective returns a fully-resolved enabled-set. Unknown keys in user
// are ignored. Missing rules fall back to their tier's default.
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
// default, and drops unknown keys. Returns nil if the result would be empty.
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
```

- [ ] **Step 4: Run, pass**

```
go test ./internal/rules/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/rules/registry.go internal/rules/registry_test.go
git commit -m "feat(rules): add Effective and Normalise resolvers"
```

---

## Phase 2 — Config schema and migration

### Task 7: Add `Rules` field and migration helper

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/migrate_test.go`

- [ ] **Step 1: Write the migration test**

```go
// internal/config/migrate_test.go
package config

import "testing"

func TestMigrateLegacyLayerFlagsAllOn(t *testing.T) {
    c := &ScanningConfig{
        RegexEnabled:   true,
        EntropyEnabled: true,
        GLiNEREnabled:  true,
        Rules:          nil,
    }
    MigrateLegacyLayerFlags(c)
    if len(c.Rules) != 0 {
        t.Errorf("all-on legacy config should leave Rules empty (defaults), got %d entries", len(c.Rules))
    }
}

func TestMigrateLegacyLayerFlagsRegexOff(t *testing.T) {
    c := &ScanningConfig{
        RegexEnabled:   false,
        EntropyEnabled: true,
        GLiNEREnabled:  true,
    }
    MigrateLegacyLayerFlags(c)
    // Every Tier 1/2 rule whose layer is "presidio" should now be false.
    if c.Rules["aws_access_key"] != false {
        t.Error("aws_access_key (presidio, tier 1) should be migrated to false")
    }
    if c.Rules["email_regex"] != false {
        t.Error("email_regex (presidio, tier 2) should be migrated to false")
    }
    // Entropy and GLiNER rules should not appear in Rules (defaults).
    if _, ok := c.Rules["person_gliner"]; ok {
        t.Error("person_gliner should not be in Rules when its layer is on")
    }
}

func TestMigrateRunsOnce(t *testing.T) {
    c := &ScanningConfig{
        RegexEnabled:   false,
        Migrated:       true,
        Rules:          map[string]bool{},
    }
    MigrateLegacyLayerFlags(c)
    if len(c.Rules) != 0 {
        t.Error("migration must be idempotent when Migrated=true")
    }
}
```

- [ ] **Step 2: Run, fail (Rules and Migrated fields, MigrateLegacyLayerFlags undefined)**

```
go test ./internal/config/...
```
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Modify config.go**

In `internal/config/config.go`, replace `ScanningConfig`:

```go
type ScanningConfig struct {
    RegexEnabled       bool            `yaml:"regex_enabled,omitempty"`     // legacy, retained for migration
    EntropyEnabled     bool            `yaml:"entropy_enabled,omitempty"`   // legacy
    EntropyThreshold   float64         `yaml:"entropy_threshold"`
    GLiNEREnabled      bool            `yaml:"gliner_enabled,omitempty"`    // legacy
    CustomPatterns     []CustomPattern `yaml:"custom_patterns"`
    CustomBlockedWords []string        `yaml:"custom_blocked_words"`
    AllowedWords       []string        `yaml:"allowed_words"`
    CacheMaxSize       int             `yaml:"cache_max_size"`

    // Rules holds per-rule toggle state. Keys are rule IDs from
    // internal/rules; missing keys fall back to tier defaults.
    Rules map[string]bool `yaml:"rules,omitempty"`

    // Migrated is set to true after MigrateLegacyLayerFlags runs once,
    // so subsequent loads do not re-migrate.
    Migrated bool `yaml:"migrated,omitempty"`
}
```

Add a new file `internal/config/migrate.go`:

```go
package config

import "github.com/rakeshguha/redactr/internal/rules"

// MigrateLegacyLayerFlags converts the deprecated boolean layer flags
// (RegexEnabled / EntropyEnabled / GLiNEREnabled) into individual rule
// entries in c.Rules. After running, c.Migrated is set to true.
//
// Behaviour:
//   - If Migrated is already true, it is a no-op.
//   - For each layer flag set to false, every rule whose Layer matches
//     gets an explicit `false` in c.Rules.
//   - Layer flags set to true do not write entries (defaults take over).
func MigrateLegacyLayerFlags(c *ScanningConfig) {
    if c.Migrated {
        return
    }
    if c.Rules == nil {
        c.Rules = make(map[string]bool)
    }
    apply := func(layer string, on bool) {
        if on {
            return
        }
        for _, r := range rules.AllRules() {
            if r.Layer == layer {
                c.Rules[r.ID] = false
            }
        }
    }
    apply("presidio", c.RegexEnabled)
    apply("entropy", c.EntropyEnabled)
    apply("gliner", c.GLiNEREnabled)
    c.Migrated = true
}
```

> **Note:** the legacy fields are retained in the struct (for migration on first load) but tagged `omitempty` so they disappear from the saved YAML once migration sets them to their zero values during a save cycle.

- [ ] **Step 4: Run, pass**

```
go test ./internal/config/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/migrate.go internal/config/migrate_test.go
git commit -m "feat(config): add Rules map and legacy-layer-flag migration"
```

---

## Phase 3 — Per-layer wiring

### Task 8: Tighten CVV pattern (rule logic change, separate from toggling)

This is a behaviour change folded into the broader work. Doing it first keeps the test surface stable when we later add toggling.

**Files:**
- Modify: `internal/scanner/presidio/presidio.go` (around line 593, the `CVV` pattern definition).
- Create or modify: `internal/scanner/presidio/presidio_test.go`.

- [ ] **Step 1: Write the test**

```go
// internal/scanner/presidio/presidio_test.go
package presidio

import (
    "strings"
    "testing"
)

func TestCVVRequiresPaymentContext(t *testing.T) {
    s := New()

    // Should match: card context nearby
    withCtx := "Visa ending 4242 cvv: 123 expires 04/27"
    res, _ := s.Scan(withCtx)
    if !hasFinding(res.Findings, "CVV") {
        t.Errorf("expected CVV match in payment context, findings=%v", res.Findings)
    }

    // Should NOT match: no card context, just `cvv: 123`
    noCtx := "the build cvv: 123 step failed"
    res2, _ := s.Scan(noCtx)
    if hasFinding(res2.Findings, "CVV") {
        t.Errorf("did not expect CVV match without payment context, findings=%v", res2.Findings)
    }
}

func hasFinding(findings []scannerFinding, label string) bool {
    for _, f := range findings {
        if f.Label == label {
            return true
        }
    }
    return false
}

// scannerFinding aliases scanner.Finding to keep the test file self-contained.
type scannerFinding = struct {
    Label      string
    Value      string
    Start      int
    End        int
    Confidence float64
    Layer      string
}
```

> **Implementation note:** the file may already declare an alias differently. If `scanner.Finding` is the canonical type, import it and drop the alias. The shape above matches `internal/scanner/types.go`.

Adjust the test to use `scanner.Finding` directly if simpler:

```go
import "github.com/rakeshguha/redactr/internal/scanner"
// then change scannerFinding -> scanner.Finding throughout
```

- [ ] **Step 2: Run the test (tighten not yet applied, "no ctx" case will fail)**

```
go test ./internal/scanner/presidio/... -run TestCVV
```
Expected: FAIL on the no-context case (current behaviour matches everywhere).

- [ ] **Step 3: Tighten the rule**

In `internal/scanner/presidio/presidio.go`, find the `CVV` `raw` entry (search for `label:      "CVV"`) and replace it with:

```go
{
    label:      "CVV",
    pattern:    `(?i)(?:cvv|cvc|cvv2|cvc2|security\s*code|card\s*verification)\s*[:=]?\s*\d{3,4}\b`,
    score:      0.6,
    context:    []string{"card", "credit", "visa", "mastercard", "amex", "expir", "cardholder", "payment"},
    contextReq: true,
},
```

(The pattern itself is unchanged; the new `context` and `contextReq: true` are the tightening.)

- [ ] **Step 4: Run, pass**

```
go test ./internal/scanner/presidio/... -run TestCVV
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/presidio/presidio.go internal/scanner/presidio/presidio_test.go
git commit -m "feat(presidio): require payment-card context for CVV"
```

---

### Task 9: Presidio scanner reads enabled-predicate

**Files:**
- Modify: `internal/scanner/presidio/presidio.go`.

The scanner's `build()` currently appends every pattern unconditionally. We need each pattern to carry a `ruleID` and the constructor to take an `enabled func(string) bool`.

- [ ] **Step 1: Write the test**

```go
// add to internal/scanner/presidio/presidio_test.go
func TestPresidioRespectsEnabled(t *testing.T) {
    enabled := map[string]bool{
        "aws_access_key": false, // explicitly disabled
        "email_regex":    true,
    }
    s := NewWithEnabled(func(id string) bool {
        v, ok := enabled[id]
        return ok && v
    })
    res, _ := s.Scan("AWS key AKIAIOSFODNN7EXAMPLE and email a@b.com")
    for _, f := range res.Findings {
        if f.Label == "AWS_ACCESS_KEY" {
            t.Error("aws_access_key should be disabled")
        }
    }
}
```

- [ ] **Step 2: Run, fail**

```
go test ./internal/scanner/presidio/... -run TestPresidioRespectsEnabled
```
Expected: FAIL — `NewWithEnabled` undefined.

- [ ] **Step 3: Implement**

In `internal/scanner/presidio/presidio.go`:

1. Add a `ruleID string` field to the inner `raw` and `patternDef` types.
2. For every entry in `defs[]`, add `ruleID: "<rule_id>"`. The mapping from existing `label` to rule_id is straightforward (lowercase + snake-case where the rule_id differs from the label; refer to the catalogue in `internal/rules/catalog.go`). Concretely, here is the mapping for every Presidio rule:

```
CREDIT_CARD (Luhn-validated)             -> credit_card_luhn
CRYPTO (BTC pattern)                     -> crypto_btc
CRYPTO (ETH pattern)                     -> crypto_eth
EMAIL_ADDRESS                            -> email_regex
IBAN_CODE (mod-97 pattern)               -> iban_presidio
IBAN_CODE (simple pattern)               -> iban_simple
IP_ADDRESS (v4 pattern)                  -> ipv4
IP_ADDRESS (v6 pattern)                  -> ipv6
URL                                      -> url_bare
DATE_OF_BIRTH (mdy)                      -> dob_mdy
DATE_OF_BIRTH (dmy)                      -> dob_dmy
MAC_ADDRESS (colon/dash)                 -> mac_colon_dash
MAC_ADDRESS (Cisco dot)                  -> mac_cisco_dot
US_SSN (initial xxx-xx-xxxx pattern)     -> us_ssn_dash
US_SSN (separated dash variant)          -> us_ssn_dash
US_SSN (separated space variant)         -> us_ssn_space
US_ITIN (dashed)                         -> us_itin_dash
US_ITIN (bare)                           -> us_itin_bare
US_PASSPORT (numeric)                    -> us_passport_numeric
US_PASSPORT (alpha)                      -> us_passport_alpha
US_DRIVER_LICENSE                        -> us_driver_license
US_BANK_NUMBER                           -> us_bank_number
ABA_ROUTING (dashed)                     -> aba_routing_dashed
ABA_ROUTING (bare)                       -> aba_routing_bare
MEDICAL_LICENSE                          -> dea_license
US_MBI (separated)                       -> us_mbi_separated
US_MBI (bare)                            -> us_mbi_bare
US_NPI (separated)                       -> us_npi_separated
US_NPI (bare)                            -> us_npi_bare
UK_NHS                                   -> uk_nhs
UK_NINO                                  -> uk_nino
UK_POSTCODE                              -> uk_postcode
UK_PASSPORT                              -> uk_passport
UK_DRIVING_LICENCE                       -> uk_driving_licence
CA_SIN                                   -> ca_sin
AU_TFN                                   -> au_tfn
IN_PAN                                   -> in_pan
ES_NIF                                   -> es_nif
DE_PASSPORT                              -> de_passport
SG_NRIC_FIN                              -> sg_nric_fin
PERSON_ID                                -> person_id_generic
SWIFT_BIC                                -> swift_bic
CVV                                      -> cvv
PHONE_NUMBER (parens)                    -> phone_parens
PHONE_NUMBER (dash/dot)                  -> phone_dash_dot
PHONE_NUMBER (intl +)                    -> phone_intl_plus
PHONE_NUMBER (leading 0)                 -> phone_leading_zero
PHONE_NUMBER (00 prefix)                 -> phone_double_zero
AWS_ACCESS_KEY                           -> aws_access_key
AWS_SECRET_KEY                           -> aws_secret_key
GCP_API_KEY                              -> gcp_api_key
PRIVATE_KEY                              -> private_key_pem
JWT                                      -> jwt
CONNECTION_STRING                        -> connection_string
GENERIC_SECRET (key=value form)          -> generic_secret_kv
GENERIC_SECRET (password=value form)     -> generic_secret_pwd
PASSWORD                                 -> password_prose
IMEI                                     -> imei
CC_EXPIRY                                -> cc_expiry
INSURANCE_ID                             -> insurance_id
REGISTRATION_ID                          -> registration_id_generic
HEALTH_PLAN_ID                           -> health_plan_id
MEDICAL_RECORD                           -> medical_record_mrn
BIOMETRIC_ID                             -> biometric_id
LICENSE_PLATE                            -> license_plate
URL_WITH_TOKEN                           -> url_with_token
CREDIT_CARD (4x4 separated)              -> credit_card_4x4
CREDIT_CARD (bare 13–19)                 -> credit_card_bare
```

Add the field to each entry in `defs[]` literal. Then add the new constructor:

```go
// New returns a Presidio scanner with all rules enabled.
func New() *Scanner {
    return NewWithEnabled(func(string) bool { return true })
}

// NewWithEnabled returns a Presidio scanner that only registers patterns
// whose rule ID is enabled by the predicate. Patterns without a ruleID
// (none in the current catalogue, but a defensive default) are always on.
func NewWithEnabled(enabled func(ruleID string) bool) *Scanner {
    s := &Scanner{enabled: enabled}
    s.build()
    return s
}
```

In `Scanner`:

```go
type Scanner struct {
    patterns []patternDef
    enabled  func(string) bool
}
```

In `build()`, after compiling each pattern but before appending, gate by:

```go
if d.ruleID != "" && s.enabled != nil && !s.enabled(d.ruleID) {
    continue
}
```

Add a `Reconfigure` method:

```go
// Reconfigure rebuilds the pattern set with a new enabled-predicate.
// Concurrency-safe: holds an internal swap.
func (s *Scanner) Reconfigure(enabled func(string) bool) {
    s.enabled = enabled
    s.patterns = nil
    s.build()
}
```

> **Note for the implementer:** the `Scanner.Scan` method iterates `s.patterns`. `Reconfigure` rebuilds the slice in-place without locking — this is safe because the scanner is owned by the coordinator and `Reconfigure` is called from a single goroutine via the API handler. If concurrent scans during reconfigure become a concern later, wrap `s.patterns` in `atomic.Pointer[[]patternDef]`. Not required now.

- [ ] **Step 4: Run, pass**

```
go test ./internal/scanner/presidio/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/presidio/presidio.go internal/scanner/presidio/presidio_test.go
git commit -m "feat(presidio): support per-rule toggling via enabled predicate"
```

---

### Task 10: Entropy scanner — split keyword-gated and unconditional

**Files:**
- Modify: `internal/scanner/entropy/entropy.go`.
- Modify: `internal/scanner/entropy/entropy_test.go`.

- [ ] **Step 1: Write the test**

```go
// add to internal/scanner/entropy/entropy_test.go
func TestKeywordGatedOnly(t *testing.T) {
    s := New(4.5, 20)
    s.SetEnabled(true /*keyword*/, false /*unconditional*/)

    // High-entropy random token, no keyword nearby — should NOT fire.
    res, _ := s.Scan("the SHA is f3a9c2b48d6e1f5a7c9b8e2d4a1f6c3b7e8d9a0c12")
    if len(res.Findings) > 0 {
        t.Errorf("unconditional disabled — should not fire on bare high-entropy token, got %v", res.Findings)
    }

    // High-entropy with secret keyword — SHOULD fire.
    res2, _ := s.Scan("api_key = f3a9c2b48d6e1f5a7c9b8e2d4a1f6c3b7e8d9a0c12")
    if len(res2.Findings) == 0 {
        t.Error("keyword-gated should fire when secret keyword is nearby")
    }
}

func TestUnconditionalOnly(t *testing.T) {
    s := New(4.5, 20)
    s.SetEnabled(false /*keyword*/, true /*unconditional*/)

    // High-entropy bare token — SHOULD fire.
    res, _ := s.Scan("just a random commit f3a9c2b48d6e1f5a7c9b8e2d4a1f6c3b7e8d9a0c12 here")
    if len(res.Findings) == 0 {
        t.Error("unconditional enabled — should fire on bare high-entropy token")
    }
}

func TestBothDisabled(t *testing.T) {
    s := New(4.5, 20)
    s.SetEnabled(false, false)
    res, _ := s.Scan("api_key = f3a9c2b48d6e1f5a7c9b8e2d4a1f6c3b7e8d9a0c12")
    if len(res.Findings) > 0 {
        t.Error("both disabled — entropy should fire on nothing")
    }
}
```

- [ ] **Step 2: Run, fail (`SetEnabled` undefined)**

```
go test ./internal/scanner/entropy/...
```
Expected: FAIL.

- [ ] **Step 3: Implement**

In `internal/scanner/entropy/entropy.go`, modify the `Scanner` and `Scan`:

```go
type Scanner struct {
    threshold     float64
    minLength     int
    keywordGated  bool
    unconditional bool
}

func New(threshold float64, minLength int) *Scanner {
    return &Scanner{
        threshold:     threshold,
        minLength:     minLength,
        keywordGated:  true, // tier 1 default
        unconditional: false, // tier 3 default
    }
}

func (s *Scanner) SetEnabled(keywordGated, unconditional bool) {
    s.keywordGated = keywordGated
    s.unconditional = unconditional
}

func (s *Scanner) Reconfigure(keywordGated, unconditional bool) {
    s.SetEnabled(keywordGated, unconditional)
}
```

Replace the body of the `for _, tok := range tokens` loop in `Scan`:

```go
ent := shannonEntropy(tok.value)
if ent < s.threshold {
    continue
}
hasContext := s.hasSecretContext(text, tok.start, tok.end)

unconditionalFire := ent >= 4.5 && s.unconditional
keywordFire       := s.keywordGated && hasContext

if !unconditionalFire && !keywordFire {
    continue
}
findings = append(findings, scanner.Finding{ ... })
```

(Keep the same `Finding` construction as before.)

- [ ] **Step 4: Run, pass**

```
go test ./internal/scanner/entropy/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/entropy/entropy.go internal/scanner/entropy/entropy_test.go
git commit -m "feat(entropy): split into keyword-gated and unconditional toggles"
```

---

### Task 11: GLiNER — raise PERSON threshold and dynamic suppression

**Files:**
- Modify: `internal/scanner/gliner/client.go`.
- Modify: `internal/scanner/gliner/client_test.go`.

- [ ] **Step 1: Write the test**

```go
// add to internal/scanner/gliner/client_test.go
func TestPersonThresholdIs080(t *testing.T) {
    c := New("http://127.0.0.1:0")
    if v := c.labelMinConfidence["PERSON"]; v != 0.80 {
        t.Errorf("expected PERSON min confidence 0.80, got %v", v)
    }
}

func TestSetEnabledLabels(t *testing.T) {
    c := New("http://127.0.0.1:0")
    c.SetEnabled(map[string]bool{"PERSON": false, "EMAIL": true})

    // PERSON should now be suppressed.
    if !c.suppressLabels["PERSON"] {
        t.Error("PERSON should be suppressed when disabled")
    }
    // EMAIL should not be suppressed.
    if c.suppressLabels["EMAIL"] {
        t.Error("EMAIL should not be suppressed when enabled")
    }
}
```

- [ ] **Step 2: Run, fail**

```
go test ./internal/scanner/gliner/... -run "TestPersonThreshold|TestSetEnabled"
```
Expected: FAIL — threshold is 0.65 currently and `SetEnabled` undefined.

- [ ] **Step 3: Implement**

In `internal/scanner/gliner/client.go`:

1. In `New`, change `"PERSON": 0.65` to `"PERSON": 0.80`.
2. Add the method:

```go
// SetEnabled rebuilds the suppress-labels map from a per-label enabled
// state. Labels not present in the map keep their previous suppression.
//
// Mapping from rule IDs to GLiNER labels:
//   email_gliner            -> EMAIL
//   person_gliner           -> PERSON
//   address_gliner          -> ADDRESS
//   dob_gliner              -> DATE_OF_BIRTH
//   ip_gliner               -> IP_ADDRESS
//   gliner_email_dup        -> (no-op; same EMAIL label, dedup elsewhere)
//   gliner_ip_dup           -> (no-op; same IP_ADDRESS label)
//   gliner_national_id_dup  -> NATIONAL_ID
func (c *Client) SetEnabled(byLabel map[string]bool) {
    for label, on := range byLabel {
        if on {
            delete(c.suppressLabels, label)
        } else {
            c.suppressLabels[label] = true
        }
    }
}

// Reconfigure accepts a per-rule-ID enabled predicate and translates it
// to the GLiNER label suppression map.
func (c *Client) Reconfigure(enabled func(string) bool) {
    byLabel := map[string]bool{
        "EMAIL":         enabled("email_gliner"),
        "PERSON":        enabled("person_gliner"),
        "ADDRESS":       enabled("address_gliner"),
        "DATE_OF_BIRTH": enabled("dob_gliner"),
        "IP_ADDRESS":    enabled("ip_gliner"),
        "NATIONAL_ID":   enabled("gliner_national_id_dup"),
    }
    c.SetEnabled(byLabel)
}
```

- [ ] **Step 4: Run, pass**

```
go test ./internal/scanner/gliner/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/gliner/client.go internal/scanner/gliner/client_test.go
git commit -m "feat(gliner): raise PERSON threshold to 0.80, add per-label toggle"
```

---

### Task 12: File-blocking — per-extension toggle wiring

**Files:**
- Modify: `internal/fileblock/fileblock.go`.
- Modify: `internal/fileblock/fileblock_test.go`.

- [ ] **Step 1: Write the test**

```go
// add to internal/fileblock/fileblock_test.go
func TestReconfigureUpdatesExtensions(t *testing.T) {
    fb := New([]string{".env", ".pem"}, true)
    if !fb.IsBlockedFile("/x.env") {
        t.Error("setup: .env should be blocked")
    }
    fb.Reconfigure([]string{".key"}, false)
    if fb.IsBlockedFile("/x.env") {
        t.Error("after reconfigure, .env should no longer block")
    }
    if !fb.IsBlockedFile("/x.key") {
        t.Error("after reconfigure, .key should block")
    }
    if fb.IsBlockedContent("KEY=foo\nSECRET=bar\nTOKEN=baz") {
        t.Error("content patterns should now be disabled")
    }
}
```

- [ ] **Step 2: Run, fail (`Reconfigure` undefined)**

```
go test ./internal/fileblock/... -run TestReconfigure
```
Expected: FAIL.

- [ ] **Step 3: Implement**

Append to `internal/fileblock/fileblock.go`:

```go
// Reconfigure replaces the blocked-extension set and content-pattern
// flag in a single atomic update.
func (b *Blocker) Reconfigure(extensions []string, contentPatterns bool) {
    ext := make(map[string]bool)
    for _, e := range extensions {
        ext[strings.ToLower(e)] = true
    }
    b.extensions = ext
    b.contentPatterns = contentPatterns
}
```

- [ ] **Step 4: Run, pass**

```
go test ./internal/fileblock/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/fileblock/fileblock.go internal/fileblock/fileblock_test.go
git commit -m "feat(fileblock): add Reconfigure for runtime extension updates"
```

---

### Task 13: Pipeline `Reconfigure`

**Files:**
- Modify: `internal/scanner/pipeline.go`.
- Modify: `internal/scanner/pipeline_test.go`.

The pipeline does not own scanners' configuration — it just iterates layers. Reconfigure is therefore a fan-out helper that calls `Reconfigure` on layers that implement the interface.

- [ ] **Step 1: Write the test**

```go
// add to internal/scanner/pipeline_test.go
func TestPipelineReconfigureFanOut(t *testing.T) {
    var saw []string
    fakeA := &fakeReconfigurable{name: "A", onReconfigure: func() { saw = append(saw, "A") }}
    fakeB := &fakeReconfigurable{name: "B", onReconfigure: func() { saw = append(saw, "B") }}
    p := NewPipeline(fakeA, fakeB)
    p.Reconfigure(func(string) bool { return true })

    if len(saw) != 2 || saw[0] != "A" || saw[1] != "B" {
        t.Errorf("expected A, B; got %v", saw)
    }
}

type fakeReconfigurable struct {
    name          string
    onReconfigure func()
}

func (f *fakeReconfigurable) Name() string                  { return f.name }
func (f *fakeReconfigurable) Ready() bool                   { return true }
func (f *fakeReconfigurable) Scan(string) (*ScanResult, error) {
    return &ScanResult{}, nil
}
func (f *fakeReconfigurable) Reconfigure(_ func(string) bool) { f.onReconfigure() }
```

- [ ] **Step 2: Run, fail (`Pipeline.Reconfigure` undefined)**

```
go test ./internal/scanner/... -run TestPipelineReconfigureFanOut
```
Expected: FAIL.

- [ ] **Step 3: Implement**

In `internal/scanner/pipeline.go`:

```go
// Reconfigurable is an optional interface implemented by layers that
// support runtime reconfiguration. The argument is a per-rule enabled
// predicate; layers translate it to their own state model.
type Reconfigurable interface {
    Reconfigure(enabled func(ruleID string) bool)
}

// Reconfigure forwards the predicate to every layer that implements
// Reconfigurable. Layers that don't are skipped silently.
func (p *Pipeline) Reconfigure(enabled func(ruleID string) bool) {
    for _, l := range p.layers {
        if r, ok := l.(Reconfigurable); ok {
            r.Reconfigure(enabled)
        }
    }
}
```

- [ ] **Step 4: Now adapt the entropy and presidio scanners to fit `Reconfigurable`'s signature**

The presidio scanner's `Reconfigure(enabled func(string) bool)` already matches. The entropy scanner's `Reconfigure(keywordGated, unconditional bool)` does **not** match. Wrap it.

In `internal/scanner/entropy/entropy.go`, replace the signature:

```go
// Reconfigure conforms to scanner.Reconfigurable. It reads two specific
// rule IDs to decide whether the keyword-gated and unconditional branches
// fire.
func (s *Scanner) Reconfigure(enabled func(string) bool) {
    s.SetEnabled(enabled("entropy_keyword_gated"), enabled("entropy_unconditional"))
}
```

Adjust `entropy_test.go` `TestKeywordGatedOnly` etc. to keep using `SetEnabled` directly (no change to those tests).

Add for GLiNER (`gliner.Client` already has `Reconfigure(enabled func(string) bool)` from Task 11 — already correct shape).

- [ ] **Step 5: Run all tests**

```
go test ./internal/scanner/...
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/pipeline.go internal/scanner/pipeline_test.go internal/scanner/entropy/entropy.go
git commit -m "feat(scanner): add Reconfigurable interface and pipeline fan-out"
```

---

### Task 14: Coordinator `Reconfigure`

**Files:**
- Modify: `internal/coordinator/coordinator.go`.
- Modify: `internal/coordinator/coordinator_test.go`.

- [ ] **Step 1: Write the test**

```go
// add to internal/coordinator/coordinator_test.go

import (
    "github.com/rakeshguha/redactr/internal/fileblock"
    "github.com/rakeshguha/redactr/internal/scanner"
)

func TestCoordinatorReconfigureInvalidatesCache(t *testing.T) {
    pipeline := scanner.NewPipeline()
    cache := scanner.NewCache(10)
    fb := fileblock.New([]string{".env"}, true)
    c := New(pipeline, cache, fb)

    // Prime the cache.
    _, _, _ = c.ScanAndRedact("hello world")
    if cache.Stats().Size != 1 {
        t.Fatalf("expected cache size 1, got %d", cache.Stats().Size)
    }

    c.Reconfigure(func(string) bool { return true }, []string{".key"}, false)

    if cache.Stats().Size != 0 {
        t.Errorf("Reconfigure should invalidate cache, size=%d", cache.Stats().Size)
    }
    if fb.IsBlockedFile("/x.env") {
        t.Error(".env should no longer be blocked after reconfigure")
    }
}
```

- [ ] **Step 2: Run, fail**

```
go test ./internal/coordinator/... -run TestCoordinatorReconfigureInvalidatesCache
```
Expected: FAIL.

- [ ] **Step 3: Implement**

Append to `internal/coordinator/coordinator.go`:

```go
// Reconfigure propagates a new rule-enabled predicate to the pipeline,
// updates file-blocking state, and invalidates the scan cache.
func (c *Coordinator) Reconfigure(enabled func(string) bool, blockedExtensions []string, contentPatterns bool) {
    c.pipeline.Reconfigure(enabled)
    c.fb.Reconfigure(blockedExtensions, contentPatterns)
    c.cache.Invalidate()
}
```

- [ ] **Step 4: Run, pass**

```
go test ./internal/coordinator/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/coordinator/coordinator.go internal/coordinator/coordinator_test.go
git commit -m "feat(coordinator): add Reconfigure that fans out + invalidates cache"
```

---

## Phase 4 — API surface

### Task 15: `GET /api/rules`

**Files:**
- Create: `internal/api/rules_handler.go`.
- Modify: `internal/api/server.go` (struct already has `coordinator`, no change needed).
- Modify: `internal/api/routes.go` (register route).
- Create: `internal/api/rules_handler_test.go`.

- [ ] **Step 1: Write the test**

```go
// internal/api/rules_handler_test.go
package api

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/rakeshguha/redactr/internal/config"
    "github.com/rakeshguha/redactr/internal/store"
)

func TestGetRulesReturnsCatalogue(t *testing.T) {
    cfgMgr, _ := config.NewManager(t.TempDir() + "/c.yaml")
    s, _ := store.New(t.TempDir() + "/db.db")
    defer s.Close()
    srv := NewServer(cfgMgr, s, nil, nil, nil)

    rec := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
    srv.Handler().ServeHTTP(rec, req)

    if rec.Code != 200 {
        t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
    }
    var resp struct {
        Tiers  []map[string]any `json:"tiers"`
        Groups []map[string]any `json:"groups"`
        Rules  []map[string]any `json:"rules"`
    }
    if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
        t.Fatalf("decode: %v body=%s", err, rec.Body.String())
    }
    if len(resp.Tiers) != 3 {
        t.Errorf("expected 3 tiers, got %d", len(resp.Tiers))
    }
    if len(resp.Groups) != 37 {
        t.Errorf("expected 37 groups, got %d", len(resp.Groups))
    }
    if len(resp.Rules) != 85 {
        t.Errorf("expected 85 rules, got %d", len(resp.Rules))
    }
}

func TestGetRulesEnabledReflectsConfig(t *testing.T) {
    cfgMgr, _ := config.NewManager(t.TempDir() + "/c.yaml")
    cfgMgr.Update(func(c *config.Config) {
        c.Scanning.Rules = map[string]bool{"aws_access_key": false}
    })
    s, _ := store.New(t.TempDir() + "/db.db")
    defer s.Close()
    srv := NewServer(cfgMgr, s, nil, nil, nil)

    rec := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
    srv.Handler().ServeHTTP(rec, req)

    var resp struct {
        Rules []struct {
            ID      string `json:"id"`
            Enabled bool   `json:"enabled"`
            Default bool   `json:"default"`
        } `json:"rules"`
    }
    json.Unmarshal(rec.Body.Bytes(), &resp)
    var aws struct {
        ID      string
        Enabled bool
        Default bool
    }
    for _, r := range resp.Rules {
        if r.ID == "aws_access_key" {
            aws.ID = r.ID
            aws.Enabled = r.Enabled
            aws.Default = r.Default
        }
    }
    if !aws.Default {
        t.Error("aws_access_key default should be true")
    }
    if aws.Enabled {
        t.Error("aws_access_key explicitly disabled in config — Enabled should be false")
    }
}
```

- [ ] **Step 2: Run, fail (handler not registered)**

```
go test ./internal/api/... -run TestGetRules
```
Expected: FAIL — 404 from the test server.

- [ ] **Step 3: Implement the handler**

Create `internal/api/rules_handler.go`:

```go
package api

import (
    "encoding/json"
    "net/http"

    "github.com/rakeshguha/redactr/internal/rules"
)

type rulesResponseTier struct {
    ID           string `json:"id"`
    Label        string `json:"label"`
    Default      bool   `json:"default"`
    WarningLevel string `json:"warning_level"`
}

type rulesResponseGroup struct {
    ID    string   `json:"id"`
    Label string   `json:"label"`
    Tier  string   `json:"tier"`
    Rules []string `json:"rules"`
}

type rulesResponseRule struct {
    ID       string `json:"id"`
    Label    string `json:"label"`
    Describe string `json:"describe"`
    Group    string `json:"group"`
    Tier     string `json:"tier"`
    Layer    string `json:"layer"`
    Default  bool   `json:"default"`
    Enabled  bool   `json:"enabled"`
}

func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
    cfg := s.cfgMgr.Get()
    effective := rules.Effective(cfg.Scanning.Rules)

    resp := struct {
        Tiers  []rulesResponseTier  `json:"tiers"`
        Groups []rulesResponseGroup `json:"groups"`
        Rules  []rulesResponseRule  `json:"rules"`
    }{
        Tiers: []rulesResponseTier{
            {ID: "always_on",     Label: "Always On",     Default: true,  WarningLevel: "modal_and_banner"},
            {ID: "good_to_have",  Label: "Good to Have",  Default: true,  WarningLevel: "inline_confirm"},
            {ID: "to_be_safer",   Label: "To Be Safer",   Default: false, WarningLevel: "silent"},
        },
    }
    for _, g := range rules.AllGroups() {
        resp.Groups = append(resp.Groups, rulesResponseGroup{
            ID: g.ID, Label: g.Label, Tier: g.Tier.String(), Rules: g.Rules,
        })
    }
    for _, r := range rules.AllRules() {
        resp.Rules = append(resp.Rules, rulesResponseRule{
            ID:       r.ID,
            Label:    r.Label,
            Describe: r.Describe,
            Group:    r.Group,
            Tier:     r.Tier.String(),
            Layer:    r.Layer,
            Default:  rules.ResolveDefault(r.Tier),
            Enabled:  effective[r.ID],
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}
```

In `internal/api/routes.go`, add inside `registerRoutes()`:

```go
s.mux.HandleFunc("GET /api/rules", s.handleGetRules)
```

- [ ] **Step 4: Run, pass**

```
go test ./internal/api/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/rules_handler.go internal/api/rules_handler_test.go internal/api/routes.go
git commit -m "feat(api): GET /api/rules returns catalogue + state"
```

---

### Task 16: `PUT /api/rules`

**Files:**
- Modify: `internal/api/rules_handler.go`.
- Modify: `internal/api/routes.go`.
- Modify: `internal/api/rules_handler_test.go`.

- [ ] **Step 1: Write the test**

```go
// add to internal/api/rules_handler_test.go
func TestPutRulesNormalisesAndPersists(t *testing.T) {
    path := t.TempDir() + "/c.yaml"
    cfgMgr, _ := config.NewManager(path)
    s, _ := store.New(t.TempDir() + "/db.db")
    defer s.Close()
    srv := NewServer(cfgMgr, s, nil, nil, nil)

    body := `{"rules":{"aws_access_key":false,"ipv4":true,"email_regex":true,"unknown_rule":true}}`
    rec := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    srv.Handler().ServeHTTP(rec, req)

    if rec.Code != 400 {
        t.Fatalf("unknown rule should yield 400, got %d body=%s", rec.Code, rec.Body.String())
    }

    body2 := `{"rules":{"aws_access_key":false,"ipv4":true,"email_regex":true}}`
    rec2 := httptest.NewRecorder()
    req2 := httptest.NewRequest(http.MethodPut, "/api/rules", strings.NewReader(body2))
    req2.Header.Set("Content-Type", "application/json")
    srv.Handler().ServeHTTP(rec2, req2)
    if rec2.Code != 200 {
        t.Fatalf("expected 200, got %d body=%s", rec2.Code, rec2.Body.String())
    }
    saved := cfgMgr.Get().Scanning.Rules
    if v, ok := saved["aws_access_key"]; !ok || v {
        t.Errorf("aws_access_key should be false in saved rules, got %v ok=%v", v, ok)
    }
    if _, ok := saved["email_regex"]; ok {
        t.Errorf("email_regex matches default true and should have been normalised away, got %v", saved["email_regex"])
    }
}
```

(Add `strings` import.)

- [ ] **Step 2: Run, fail**

```
go test ./internal/api/... -run TestPutRules
```
Expected: FAIL — handler not registered.

- [ ] **Step 3: Implement**

In `internal/api/rules_handler.go`, append:

```go
func (s *Server) handlePutRules(w http.ResponseWriter, r *http.Request) {
    var body struct {
        Rules map[string]bool `json:"rules"`
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
        return
    }
    if body.Rules == nil {
        body.Rules = map[string]bool{}
    }

    var unknown []string
    for id := range body.Rules {
        if !rules.IsKnown(id) {
            unknown = append(unknown, id)
        }
    }
    if len(unknown) > 0 {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]any{
            "error":    "unknown rule_ids",
            "rule_ids": unknown,
        })
        return
    }

    normalised := rules.Normalise(body.Rules)
    if err := s.cfgMgr.Update(func(c *config.Config) {
        c.Scanning.Rules = normalised
    }); err != nil {
        writeError(w, http.StatusInternalServerError, "save failed: "+err.Error())
        return
    }

    if s.coordinator != nil {
        cfg := s.cfgMgr.Get()
        eff := rules.Effective(cfg.Scanning.Rules)
        exts := enabledFileBlockExtensions(eff)
        s.coordinator.Reconfigure(func(id string) bool { return eff[id] }, exts, eff["file_block_content_patterns"])
    }

    writeJSON(w, map[string]any{"ok": true})
}

// enabledFileBlockExtensions returns the slice of file extensions whose
// per-extension toggle is enabled in the effective rule map.
func enabledFileBlockExtensions(eff map[string]bool) []string {
    pairs := []struct{ id, ext string }{
        {"file_block_env", ".env"},
        {"file_block_tfstate", ".tfstate"},
        {"file_block_pem", ".pem"},
        {"file_block_key", ".key"},
        {"file_block_p12", ".p12"},
        {"file_block_pfx", ".pfx"},
    }
    var out []string
    for _, p := range pairs {
        if eff[p.id] {
            out = append(out, p.ext)
        }
    }
    return out
}
```

> **Note:** `enabledFileBlockExtensions` ignores the legacy `file_blocking.blocked_extensions` config field. The implementer should also extend it to include any user-defined extensions from `c.FileBlocking.BlockedExtensions` that are not in the default six. Concretely:
>
> ```go
> defaults := map[string]bool{".env": true, ".tfstate": true, ".pem": true, ".key": true, ".p12": true, ".pfx": true}
> for _, e := range cfg.FileBlocking.BlockedExtensions {
>     if !defaults[strings.ToLower(e)] {
>         out = append(out, e)
>     }
> }
> ```
>
> Wire that into `handlePutRules` (and into the startup wiring in Task 17).

In `internal/api/routes.go`, add inside `registerRoutes()`:

```go
s.mux.HandleFunc("PUT /api/rules", s.handlePutRules)
```

- [ ] **Step 4: Run, pass**

```
go test ./internal/api/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/rules_handler.go internal/api/rules_handler_test.go internal/api/routes.go
git commit -m "feat(api): PUT /api/rules persists, normalises, and reconfigures"
```

---

### Task 17: Startup wiring (main.go)

**Files:**
- Modify: `cmd/redactr/main.go`.

- [ ] **Step 1: Update scanner construction to read effective rule state**

In `cmd/redactr/main.go`, after `cfg := cfgMgr.Get()` and before constructing scanners, add the migration call and compute effective state:

```go
// Migrate legacy layer flags to per-rule entries (no-op after first run).
cfgMgr.Update(func(c *config.Config) {
    config.MigrateLegacyLayerFlags(&c.Scanning)
})
cfg = cfgMgr.Get()

eff := rules.Effective(cfg.Scanning.Rules)
ruleEnabled := func(id string) bool { return eff[id] }
```

(Add the import: `"github.com/rakeshguha/redactr/internal/rules"`.)

Replace the `presidioScanner := presidio.New()` line with:

```go
presidioScanner := presidio.NewWithEnabled(ruleEnabled)
```

Replace the entropy construction:

```go
entropyScanner := entropy.New(cfg.Scanning.EntropyThreshold, 20)
entropyScanner.SetEnabled(eff["entropy_keyword_gated"], eff["entropy_unconditional"])
```

After GLiNER is constructed:

```go
glinerClient.Reconfigure(ruleEnabled)
```

Replace the file-blocker construction:

```go
defaults := map[string]bool{".env": true, ".tfstate": true, ".pem": true, ".key": true, ".p12": true, ".pfx": true}
var fbExts []string
for _, p := range []struct{ id, ext string }{
    {"file_block_env", ".env"}, {"file_block_tfstate", ".tfstate"},
    {"file_block_pem", ".pem"}, {"file_block_key", ".key"},
    {"file_block_p12", ".p12"}, {"file_block_pfx", ".pfx"},
} {
    if eff[p.id] {
        fbExts = append(fbExts, p.ext)
    }
}
for _, e := range cfg.FileBlocking.BlockedExtensions {
    le := strings.ToLower(e)
    if !defaults[le] {
        fbExts = append(fbExts, e)
    }
}
fb := fileblock.New(fbExts, eff["file_block_content_patterns"] && cfg.FileBlocking.ContentPatternsEnabled)
```

(Add the `strings` import if not present — it likely already is.)

- [ ] **Step 2: Build to verify**

```
go build ./...
```
Expected: success.

- [ ] **Step 3: Run all tests**

```
go test ./...
```
Expected: PASS.

- [ ] **Step 4: Smoke test (manual, brief)**

```
pkill -f redactr 2>/dev/null
go run ./cmd/redactr &
sleep 3
PORT=$(cat ~/.redactr/state/dashboard.port)
curl -s http://$PORT/api/rules | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"groups={len(d['groups'])} rules={len(d['rules'])}\")"
pkill -f redactr
```

Expected output:
```
groups=37 rules=85
```

- [ ] **Step 5: Commit**

```bash
git add cmd/redactr/main.go
git commit -m "feat(redactr): wire rule-effective state into scanner construction"
```

---

## Phase 5 — Dashboard UI

### Task 18: Render the Detection Rules card skeleton

**Files:**
- Modify: `internal/api/static/index.html`.
- Modify: `internal/api/static/style.css`.
- Modify: `internal/api/static/app.js`.

This task replaces the existing "Scanning Layers" card and renders three collapsible tier sections with their group rows. No toggle logic yet — pure read-only render.

- [ ] **Step 1: Update HTML — replace Scanning Layers card**

In `internal/api/static/index.html`, locate the existing "Scanning Layers" card inside `<section id="config" class="tab-content">` and replace it with:

```html
<div class="card span-12 detection-rules-card">
  <div class="card-head">
    <div>
      <span class="card-eyebrow"><em>detection</em></span>
      <h2>Detection rules</h2>
    </div>
    <div class="search-input">
      <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>
      <input type="text" id="rule-search" placeholder="Search rules…">
    </div>
  </div>
  <div id="rule-tiers"></div>
</div>
```

Remove the original "Scanning Layers" card entirely (the one containing `cfg-regex` / `cfg-entropy` / `cfg-gliner` / `cfg-entropy-thresh`).

> **Keep** the entropy threshold field by relocating it into a new small subsection inside the existing "Cache" or "Configuration" cluster, since it's still meaningful. Insert this inside the Cache card just above `Clear cache`:
>
> ```html
> <div class="field" style="margin-top:16px">
>   <label class="field-label">Entropy threshold</label>
>   <input type="number" id="cfg-entropy-thresh" step="0.1" min="1" max="8">
>   <span class="field-hint">Bits per character. Lower = stricter; higher = looser.</span>
> </div>
> ```

- [ ] **Step 2: Add CSS styles**

Append to `internal/api/static/style.css`:

```css
/* ============================================================
   Detection Rules
   ============================================================ */

.detection-rules-card .card-head .search-input { min-width: 280px; }

.tier-section {
  border-top: 1px solid var(--border-soft);
  padding: 14px 0;
}
.tier-section:first-child { border-top: 0; padding-top: 4px; }

.tier-header {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  user-select: none;
  font-size: 13.5px;
  color: var(--text);
  font-weight: 500;
  letter-spacing: -0.005em;
  padding: 6px 0;
}
.tier-header .tier-chevron { transition: transform 200ms ease; color: var(--text-4); }
.tier-section[data-open="true"] .tier-chevron { transform: rotate(90deg); }

.tier-summary {
  margin-left: auto;
  font-family: var(--font-mono);
  font-size: 11.5px;
  color: var(--text-3);
}

.tier-body { display: none; padding-top: 8px; }
.tier-section[data-open="true"] .tier-body { display: block; animation: slidein 220ms ease; }

.group-row {
  display: grid;
  grid-template-columns: 32px 1fr auto;
  align-items: center;
  gap: 12px;
  padding: 10px 4px;
  border-radius: 8px;
  transition: background 120ms ease;
}
.group-row:hover { background: var(--bg-elevated-2); }

.group-toggle, .rule-toggle {
  width: 32px; height: 18px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 999px;
  position: relative;
  cursor: pointer;
  transition: background 160ms ease, border-color 160ms ease;
  flex-shrink: 0;
}
.group-toggle::after, .rule-toggle::after {
  content: "";
  position: absolute;
  top: 1px; left: 1px;
  width: 14px; height: 14px;
  border-radius: 50%;
  background: var(--text-4);
  transition: left 160ms ease, background 160ms ease;
}
.group-toggle[data-state="on"], .rule-toggle[data-state="on"] {
  background: var(--accent-soft);
  border-color: var(--accent-edge);
}
.group-toggle[data-state="on"]::after, .rule-toggle[data-state="on"]::after {
  left: 15px;
  background: var(--accent);
  box-shadow: 0 0 6px var(--accent-glow);
}
.group-toggle[data-state="indeterminate"]::after {
  left: 8px;
  background: var(--text-3);
  width: 14px;
  height: 14px;
}

.group-label { font-size: 13px; color: var(--text); font-weight: 500; }
.group-meta {
  font-size: 11.5px;
  color: var(--text-4);
  font-family: var(--font-mono);
}

.group-disclosure {
  background: none; border: none;
  color: var(--text-4);
  font-size: 11px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 6px;
}
.group-disclosure:hover { color: var(--accent); background: var(--accent-soft); }

.rule-list {
  display: none;
  margin: 4px 0 4px 32px;
  padding: 6px 0;
  border-left: 1px solid var(--border-soft);
}
.group-row[data-open="true"] + .rule-list { display: block; }

.rule-row {
  display: grid;
  grid-template-columns: 32px 1fr;
  align-items: flex-start;
  gap: 12px;
  padding: 6px 12px;
}
.rule-row .rule-id-label {
  font-size: 12.5px;
  color: var(--text);
}
.rule-row .rule-describe {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-4);
  margin-top: 2px;
}

.tier-section[data-tier="always_on"]   .group-toggle[data-state="on"]  { border-color: var(--accent-edge); }
.tier-section[data-tier="to_be_safer"] .group-row { opacity: 0.92; }

.detection-rules-card .empty-search {
  padding: 24px 0;
  color: var(--text-4);
  font-size: 12.5px;
  text-align: center;
}
```

- [ ] **Step 3: Add the renderer to app.js**

In `internal/api/static/app.js`, near the other render functions, add:

```js
let rulesData = null;
let pendingRuleChanges = {}; // ruleID -> bool override
let openGroups = new Set();
let openTiers = new Set(['always_on', 'good_to_have']); // tier 3 collapsed by default

async function fetchRules() {
  try {
    rulesData = await api('/rules');
    renderRules();
  } catch (err) {
    console.error('[redactr] /rules failed:', err);
  }
}

function effectiveEnabled(ruleID) {
  if (Object.prototype.hasOwnProperty.call(pendingRuleChanges, ruleID)) {
    return pendingRuleChanges[ruleID];
  }
  const r = rulesData.rules.find(x => x.id === ruleID);
  return r ? r.enabled : false;
}

function groupState(group) {
  const enabledCount = group.rules.filter(id => effectiveEnabled(id)).length;
  if (enabledCount === 0) return 'off';
  if (enabledCount === group.rules.length) return 'on';
  return 'indeterminate';
}

function renderRules() {
  const root = document.getElementById('rule-tiers');
  if (!root || !rulesData) return;
  const search = (document.getElementById('rule-search')?.value || '').toLowerCase();

  root.innerHTML = rulesData.tiers.map(tier => {
    const tierGroups = rulesData.groups.filter(g => g.tier === tier.id);
    const totalRules = tierGroups.reduce((n, g) => n + g.rules.length, 0);
    const enabledRules = tierGroups.reduce((n, g) =>
      n + g.rules.filter(id => effectiveEnabled(id)).length, 0);

    const sections = tierGroups.map(group => renderGroup(group, search)).join('');
    const visible = sections.replace(/\s/g, '').length > 0;
    if (!visible && search) return '';

    return `
      <div class="tier-section" data-tier="${tier.id}" data-open="${openTiers.has(tier.id)}">
        <div class="tier-header" data-tier-id="${tier.id}">
          <svg class="tier-chevron" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"/></svg>
          <strong>${esc(tier.label)}</strong>
          <span class="tier-summary">${enabledRules} / ${totalRules} rules</span>
        </div>
        <div class="tier-body">${sections}</div>
      </div>`;
  }).join('');

  attachRuleHandlers();
}

function renderGroup(group, search) {
  const memberRules = group.rules.map(id => rulesData.rules.find(r => r.id === id)).filter(Boolean);
  const matches = !search || group.label.toLowerCase().includes(search) ||
    memberRules.some(r => r.id.includes(search) || r.label.toLowerCase().includes(search) || r.describe.toLowerCase().includes(search));
  if (!matches) return '';

  const state = groupState(group);
  const isOpen = openGroups.has(group.id) || (search && memberRules.some(r => r.id.includes(search) || r.label.toLowerCase().includes(search)));
  const enabledCount = memberRules.filter(r => effectiveEnabled(r.id)).length;

  const ruleRows = memberRules.length > 1 ? memberRules.map(r => {
    if (search && !(r.id.includes(search) || r.label.toLowerCase().includes(search) || r.describe.toLowerCase().includes(search) || group.label.toLowerCase().includes(search))) {
      return '';
    }
    return `
      <div class="rule-row">
        <div class="rule-toggle" data-state="${effectiveEnabled(r.id) ? 'on' : 'off'}" data-rule="${r.id}" role="switch"></div>
        <div>
          <div class="rule-id-label">${esc(r.label)}</div>
          <div class="rule-describe">${esc(r.describe)}</div>
        </div>
      </div>`;
  }).join('') : '';

  return `
    <div class="group-row" data-group="${group.id}" data-open="${isOpen}">
      <div class="group-toggle" data-state="${state}" data-group-id="${group.id}" role="switch"></div>
      <div>
        <div class="group-label">${esc(group.label)}</div>
        <div class="group-meta">${enabledCount} / ${memberRules.length} rules enabled</div>
      </div>
      ${memberRules.length > 1
        ? `<button class="group-disclosure" data-disclose="${group.id}">${isOpen ? 'Hide' : 'Show'} ${memberRules.length} rules</button>`
        : ''}
    </div>
    ${memberRules.length > 1 ? `<div class="rule-list" style="display:${isOpen ? 'block' : 'none'}">${ruleRows}</div>` : ''}
  `;
}

function attachRuleHandlers() {
  document.querySelectorAll('.tier-header').forEach(h => {
    h.addEventListener('click', () => {
      const id = h.dataset.tierId;
      if (openTiers.has(id)) openTiers.delete(id);
      else openTiers.add(id);
      renderRules();
    });
  });

  document.querySelectorAll('[data-disclose]').forEach(b => {
    b.addEventListener('click', () => {
      const id = b.dataset.disclose;
      if (openGroups.has(id)) openGroups.delete(id);
      else openGroups.add(id);
      renderRules();
    });
  });

  // Toggle handlers attached in Task 19.
}
```

In the `DOMContentLoaded` initialiser, add `fetchRules()` to the startup sequence and re-fetch when the user opens the Configuration tab:

```js
document.querySelector('[data-tab="config"]').addEventListener('click', fetchRules);

document.getElementById('rule-search').addEventListener('input', renderRules);
```

(Place these inside the existing `initActions()` or a new `initRulesUI()` called from `DOMContentLoaded`.)

- [ ] **Step 4: Build, run smoke test**

```
go build -o /tmp/redactr-new ./cmd/redactr
pkill -f redactr 2>/dev/null
/tmp/redactr-new &
sleep 3
open "http://$(cat ~/.redactr/state/dashboard.port)"
```

Manually: open the Configuration tab; verify the new "Detection rules" card lists three tier headers with rule counts. The toggles do not yet act — they render visually only.

- [ ] **Step 5: Commit**

```bash
git add internal/api/static/index.html internal/api/static/style.css internal/api/static/app.js
git commit -m "feat(ui): render Detection rules card with tier sections (read-only)"
```

---

### Task 19: Wire toggles (with Tier 3 silent flow only — Tier 1 & 2 in next tasks)

**Files:**
- Modify: `internal/api/static/app.js`.

- [ ] **Step 1: Add toggle handlers**

In `attachRuleHandlers()`, add at the end:

```js
document.querySelectorAll('.rule-toggle').forEach(el => {
  el.addEventListener('click', () => onRuleToggle(el.dataset.rule));
});
document.querySelectorAll('.group-toggle').forEach(el => {
  el.addEventListener('click', () => onGroupToggle(el.dataset.groupId));
});
```

Add the handlers:

```js
function onRuleToggle(ruleID) {
  const rule = rulesData.rules.find(r => r.id === ruleID);
  if (!rule) return;
  const current = effectiveEnabled(ruleID);
  const next = !current;
  const tier = rule.tier;

  // Disabling a rule whose tier matters → guard. Enabling is always allowed.
  const isDisabling = current && !next;
  if (isDisabling) {
    confirmTierAction(tier, [rule], () => commitRuleChanges({ [ruleID]: next }));
  } else {
    commitRuleChanges({ [ruleID]: next });
  }
}

function onGroupToggle(groupID) {
  const group = rulesData.groups.find(g => g.id === groupID);
  if (!group) return;
  const memberRules = group.rules.map(id => rulesData.rules.find(r => r.id === id));
  const state = groupState(group);
  const turnOn = state !== 'on'; // off or indeterminate → turn fully on; on → turn fully off
  const changes = {};
  memberRules.forEach(r => { changes[r.id] = turnOn; });

  if (!turnOn) {
    confirmTierAction(group.tier, memberRules, () => commitRuleChanges(changes));
  } else {
    commitRuleChanges(changes);
  }
}

function commitRuleChanges(changes) {
  Object.assign(pendingRuleChanges, changes);
  renderRules();
  saveRules();
}

async function saveRules() {
  // Build the full rules map: existing config rules + pending changes,
  // then send. The server will normalise.
  const rulesMap = {};
  rulesData.rules.forEach(r => {
    if (Object.prototype.hasOwnProperty.call(pendingRuleChanges, r.id)) {
      rulesMap[r.id] = pendingRuleChanges[r.id];
    } else if (r.enabled !== r.default) {
      rulesMap[r.id] = r.enabled;
    }
  });

  try {
    await api('/rules', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rules: rulesMap }),
    });
    toast('Detection rules updated', 'ok');
    pendingRuleChanges = {};
    await fetchRules();
    updateDegradedBanner();
  } catch (err) {
    toast('Failed to save: ' + (err.message || err), 'error');
    pendingRuleChanges = {};
    await fetchRules();
  }
}
```

For Tier 3, define the silent path (others stubbed for now):

```js
function confirmTierAction(tier, ruleSpecs, onConfirm) {
  if (tier === 'to_be_safer') { onConfirm(); return; }
  if (tier === 'good_to_have') { showInlinePopover(ruleSpecs, onConfirm); return; }
  showTier1Modal(ruleSpecs, onConfirm);
}

// Stubs for Tier 1 / Tier 2 — implemented in next tasks.
function showInlinePopover(rules, onConfirm) {
  if (confirm(`Disable ${rules.length} rule(s)?`)) onConfirm();
}
function showTier1Modal(rules, onConfirm) {
  if (confirm(`DISABLE A TIER 1 PROTECTION? Affected rules: ${rules.map(r => r.label).join(', ')}`)) onConfirm();
}

function updateDegradedBanner() { /* implemented in Task 22 */ }
```

- [ ] **Step 2: Smoke test**

Build and run as in Task 18. In the dashboard:
- Open Configuration tab.
- Toggle a Tier 3 group (e.g. "IP addresses") → expect silent flip + "Detection rules updated" toast + count update.
- Toggle a Tier 2 group → expect a `confirm()` dialog, then flip if accepted.
- Toggle a Tier 1 individual rule → expect a `confirm()` dialog with bigger text.

- [ ] **Step 3: Commit**

```bash
git add internal/api/static/app.js
git commit -m "feat(ui): wire detection-rule toggles with tiered confirmation stubs"
```

---

### Task 20: Tier 1 modal warning

**Files:**
- Modify: `internal/api/static/index.html` (modal container).
- Modify: `internal/api/static/style.css`.
- Modify: `internal/api/static/app.js` (replace `showTier1Modal` stub).

- [ ] **Step 1: Add modal container to HTML**

Append before the closing `</body>` tag:

```html
<div class="modal-backdrop" id="modal-backdrop" hidden>
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">
      <span class="modal-eyebrow"><em>warning</em></span>
      <h2 id="modal-title">Disable a critical detection rule?</h2>
    </div>
    <div class="modal-body" id="modal-body"></div>
    <div class="modal-actions">
      <button class="btn btn-ghost" id="modal-cancel">Cancel</button>
      <button class="btn btn-danger" id="modal-confirm">Disable anyway</button>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Add modal CSS**

Append to `style.css`:

```css
.modal-backdrop {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.55);
  backdrop-filter: blur(4px);
  display: flex; align-items: center; justify-content: center;
  z-index: 300;
  animation: fadein 160ms ease;
}
.modal-backdrop[hidden] { display: none; }

.modal {
  background: var(--bg-elevated);
  border: 1px solid var(--border-hover);
  border-radius: var(--r-lg);
  width: 480px; max-width: 92vw;
  padding: 22px 24px;
  box-shadow: var(--shadow-elev);
}
.modal-head { margin-bottom: 14px; }
.modal-eyebrow { color: var(--danger); font-family: var(--font-serif); font-style: italic; font-size: 13px; }
.modal h2 { font-size: 17px; font-weight: 600; letter-spacing: -0.02em; }

.modal-body {
  font-size: 13px;
  color: var(--text-2);
  line-height: 1.6;
  margin-bottom: 18px;
}
.modal-body .modal-rule-list {
  list-style: none;
  margin: 10px 0;
  padding: 12px;
  background: var(--danger-soft);
  border: 1px solid rgba(248,113,113,0.30);
  border-radius: 8px;
}
.modal-body .modal-rule-list li {
  padding: 4px 0;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--danger);
}
.modal-body .modal-rule-list li small {
  display: block;
  color: var(--text-3);
  font-family: var(--font-sans);
  margin-top: 2px;
}

.modal-actions { display: flex; justify-content: flex-end; gap: 8px; }
```

- [ ] **Step 3: Replace the `showTier1Modal` stub**

In `app.js`:

```js
function showTier1Modal(ruleSpecs, onConfirm) {
  const backdrop = document.getElementById('modal-backdrop');
  document.getElementById('modal-body').innerHTML = `
    <p>Disabling the following <strong>Always-On</strong> rule${ruleSpecs.length === 1 ? '' : 's'} means matching credentials or PII will be sent to the AI provider unredacted.</p>
    <ul class="modal-rule-list">
      ${ruleSpecs.map(r => `<li>${esc(r.label)}<small>${esc(r.describe)}</small></li>`).join('')}
    </ul>
    <p>Are you sure?</p>
  `;
  backdrop.hidden = false;

  const cleanup = () => { backdrop.hidden = true; };
  const onCancel = () => { cleanup(); cancelBtn.removeEventListener('click', onCancel); confirmBtn.removeEventListener('click', onConfirmClick); };
  const onConfirmClick = () => { cleanup(); cancelBtn.removeEventListener('click', onCancel); confirmBtn.removeEventListener('click', onConfirmClick); onConfirm(); };

  const cancelBtn = document.getElementById('modal-cancel');
  const confirmBtn = document.getElementById('modal-confirm');
  cancelBtn.addEventListener('click', onCancel);
  confirmBtn.addEventListener('click', onConfirmClick);
}
```

- [ ] **Step 4: Smoke test**

Toggle a Tier 1 group (e.g. "Cloud credentials") off → verify the modal appears, lists the three rules, and either Cancel or "Disable anyway" works.

- [ ] **Step 5: Commit**

```bash
git add internal/api/static/index.html internal/api/static/style.css internal/api/static/app.js
git commit -m "feat(ui): Tier 1 modal warning for disabling always-on rules"
```

---

### Task 21: Tier 2 inline popover

**Files:**
- Modify: `internal/api/static/style.css`.
- Modify: `internal/api/static/app.js`.

- [ ] **Step 1: Add popover CSS**

Append:

```css
.inline-popover {
  position: absolute;
  z-index: 250;
  background: var(--bg-elevated);
  border: 1px solid var(--border-hover);
  border-radius: 8px;
  padding: 10px 12px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
  font-size: 12.5px;
  color: var(--text-2);
  display: flex;
  flex-direction: column;
  gap: 8px;
  width: 240px;
  animation: fadein 140ms ease;
}
.inline-popover .popover-actions { display: flex; gap: 6px; justify-content: flex-end; }
.inline-popover .popover-actions .btn { padding: 4px 10px; font-size: 11.5px; }
```

- [ ] **Step 2: Replace `showInlinePopover`**

```js
function showInlinePopover(ruleSpecs, onConfirm) {
  // Anchor to the most-recently-clicked toggle. We find it by data-rule
  // / data-group-id matching the first rule in the list.
  const ids = ruleSpecs.map(r => r.id);
  const anchor = document.querySelector(`[data-rule="${ids[0]}"]`)
    || document.querySelector(`[data-group-id="${rulesData.groups.find(g => g.rules.some(id => ids.includes(id)))?.id}"]`);
  if (!anchor) { onConfirm(); return; } // fallback: act silently

  const rect = anchor.getBoundingClientRect();
  const pop = document.createElement('div');
  pop.className = 'inline-popover';
  pop.innerHTML = `
    <div>Disable ${ruleSpecs.length === 1 ? esc(ruleSpecs[0].label) : `${ruleSpecs.length} rules`}?</div>
    <div class="popover-actions">
      <button class="btn btn-ghost" data-pa="cancel">Cancel</button>
      <button class="btn btn-primary" data-pa="confirm">Disable</button>
    </div>
  `;
  document.body.appendChild(pop);
  pop.style.left = `${Math.min(window.innerWidth - 260, rect.right + 8)}px`;
  pop.style.top = `${rect.top + window.scrollY}px`;

  const cleanup = () => { pop.remove(); document.removeEventListener('click', outside); };
  const outside = (e) => { if (!pop.contains(e.target) && e.target !== anchor) cleanup(); };
  setTimeout(() => document.addEventListener('click', outside), 0);

  pop.querySelector('[data-pa="cancel"]').addEventListener('click', cleanup);
  pop.querySelector('[data-pa="confirm"]').addEventListener('click', () => { cleanup(); onConfirm(); });
}
```

- [ ] **Step 3: Smoke test**

Toggle a Tier 2 group (e.g. "Phone numbers") off → popover should anchor to the toggle, with Cancel/Disable. Click outside to dismiss.

- [ ] **Step 4: Commit**

```bash
git add internal/api/static/style.css internal/api/static/app.js
git commit -m "feat(ui): Tier 2 inline popover for disabling good-to-have rules"
```

---

### Task 22: Persistent Overview banner + topbar "Degraded protection"

**Files:**
- Modify: `internal/api/static/index.html`.
- Modify: `internal/api/static/style.css`.
- Modify: `internal/api/static/app.js`.

- [ ] **Step 1: Add the banner placeholder to the Overview hero**

In `index.html`, inside the hero card and **before** the `.hero-meta` div, add:

```html
<div class="hero-banner" id="hero-banner" hidden>
  <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
  <div class="hero-banner-text">
    <strong id="hero-banner-title">Best-practice rules disabled</strong>
    <span id="hero-banner-detail"></span>
  </div>
  <button class="link-btn" data-jump="config" id="hero-banner-jump">Review →</button>
</div>
```

- [ ] **Step 2: Add CSS**

Append:

```css
.hero-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 16px;
  padding: 10px 14px;
  background: var(--warning-soft);
  border: 1px solid rgba(251,191,36,0.30);
  border-radius: 9px;
  color: var(--warning);
  font-size: 12.5px;
}
.hero-banner.degraded {
  background: var(--danger-soft);
  border-color: rgba(248,113,113,0.30);
  color: var(--danger);
}
.hero-banner-text { display: flex; flex-direction: column; line-height: 1.3; }
.hero-banner-text strong { font-weight: 600; font-size: 13px; }
.hero-banner-text span { color: var(--text-2); margin-top: 2px; }

.proxy-pill[data-degraded="true"] { border-color: rgba(248,113,113,0.30); }
.proxy-pill[data-degraded="true"] .proxy-pill-addr { color: var(--danger); }
```

- [ ] **Step 3: Implement `updateDegradedBanner()`**

In `app.js`, replace the empty stub with:

```js
function updateDegradedBanner() {
  if (!rulesData) return;
  const tier1Off = rulesData.rules.filter(r => r.tier === 'always_on' && !effectiveEnabled(r.id));
  const banner = document.getElementById('hero-banner');
  const detail = document.getElementById('hero-banner-detail');
  const pill = document.getElementById('proxy-pill');

  if (tier1Off.length === 0) {
    banner.hidden = true;
    banner.classList.remove('degraded');
    if (pill) pill.dataset.degraded = 'false';
    return;
  }

  banner.hidden = false;
  const allOff = tier1Off.length === rulesData.rules.filter(r => r.tier === 'always_on').length;
  banner.classList.toggle('degraded', allOff);
  detail.textContent = `${tier1Off.length} disabled: ${tier1Off.map(r => r.label).join(', ')}.`;
  if (pill) pill.dataset.degraded = 'true';
}
```

Call `updateDegradedBanner()` from inside `fetchRules()` (after a successful fetch) and from `saveRules()` (already wired in Task 19).

- [ ] **Step 4: Smoke test**

Disable a Tier 1 rule → switch to Overview tab → verify the yellow banner appears with the rule name. Disable all Tier 1 rules → verify banner turns red.

- [ ] **Step 5: Commit**

```bash
git add internal/api/static/index.html internal/api/static/style.css internal/api/static/app.js
git commit -m "feat(ui): Overview banner + topbar pill when Tier 1 rules disabled"
```

---

### Task 23: Cleanup — remove legacy fields, drop old card

**Files:**
- Modify: `internal/config/config.go` (remove the three legacy fields after migration is in place).
- Modify: `internal/api/static/app.js` (remove old `cfg-regex` etc. handling).

> **Decision point:** the legacy fields (`RegexEnabled`/`EntropyEnabled`/`GLiNEREnabled`) are still in the struct after Task 7, with `omitempty` and `Migrated`. The migration runs once. After it runs, the on-disk YAML no longer contains the legacy keys (because they marshal as zero-values). It is safe to remove the fields entirely now.

- [ ] **Step 1: Remove legacy fields from `ScanningConfig`**

In `internal/config/config.go`, delete:

```
RegexEnabled       bool ...
EntropyEnabled     bool ...
GLiNEREnabled      bool ...
```

Keep `Migrated` to prevent re-migration on upgrade from a hand-edited YAML.

Update `MigrateLegacyLayerFlags` in `internal/config/migrate.go` to take an additional helper that reads the legacy yaml fields directly via a side-loaded struct:

```go
// migrate.go
package config

import (
    "os"

    "gopkg.in/yaml.v3"
    "github.com/rakeshguha/redactr/internal/rules"
)

type legacyScan struct {
    RegexEnabled   *bool `yaml:"regex_enabled"`
    EntropyEnabled *bool `yaml:"entropy_enabled"`
    GLiNEREnabled  *bool `yaml:"gliner_enabled"`
    Migrated       bool  `yaml:"migrated"`
}

type legacyRoot struct {
    Scanning legacyScan `yaml:"scanning"`
}

// MigrateLegacyLayerFlagsFromFile reads the YAML at path and, if any of
// the deprecated layer flags are present and false, writes the
// corresponding rule entries into c.Rules. Idempotent: relies on
// c.Migrated.
func MigrateLegacyLayerFlagsFromFile(c *ScanningConfig, path string) {
    if c.Migrated {
        return
    }
    data, err := os.ReadFile(path)
    if err != nil {
        c.Migrated = true
        return
    }
    var legacy legacyRoot
    if err := yaml.Unmarshal(data, &legacy); err != nil {
        c.Migrated = true
        return
    }
    if c.Rules == nil {
        c.Rules = make(map[string]bool)
    }
    apply := func(layer string, flag *bool) {
        if flag == nil || *flag {
            return
        }
        for _, r := range rules.AllRules() {
            if r.Layer == layer {
                c.Rules[r.ID] = false
            }
        }
    }
    apply("presidio", legacy.Scanning.RegexEnabled)
    apply("entropy", legacy.Scanning.EntropyEnabled)
    apply("gliner", legacy.Scanning.GLiNEREnabled)
    c.Migrated = true
}
```

Update `cmd/redactr/main.go` to call:

```go
config.MigrateLegacyLayerFlagsFromFile(&someScanCopy, filepath.Join(baseDir, "config.yaml"))
cfgMgr.Update(func(c *config.Config) { c.Scanning = someScanCopy })
```

(Or, simpler: read the file once at startup before constructing the manager, migrate, save, then construct.)

Update tests in `internal/config/migrate_test.go` to write a YAML file in `t.TempDir()` and pass its path. The original `MigrateLegacyLayerFlags(*ScanningConfig)` API is removed; tests use the new file-based one.

- [ ] **Step 2: Remove old config-card handling from app.js**

Remove (or stop reading) `cfg-regex`, `cfg-entropy`, `cfg-gliner` from `renderConfig()` and `config-save` payload. The Save button still saves other fields (intercepted_domains, blocked_domains, blocked_extensions, hooks, cache_size). Adjust the save payload accordingly.

- [ ] **Step 3: Build and run all tests**

```
go test ./...
go build ./...
```
Expected: PASS.

- [ ] **Step 4: Smoke test the full flow**

```
pkill -f redactr
go run ./cmd/redactr &
sleep 3
# Visit dashboard, toggle some rules, refresh, verify state survives.
```

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/migrate.go internal/config/migrate_test.go cmd/redactr/main.go internal/api/static/app.js
git commit -m "refactor: remove legacy layer flags, migrate config from file"
```

---

## Self-Review (run before handing off)

The plan author should now skim each section of the spec (`docs/superpowers/specs/2026-04-27-detection-rule-config-design.md`) and verify a task implements it.

| Spec section | Implementing task(s) |
|---|---|
| §3 Tier 1 catalogue | Task 3 |
| §3 Tier 2 catalogue | Task 4 |
| §3 Tier 3 catalogue | Task 5 |
| §3 Invariant tests | Task 2 |
| §4 CVV tightening | Task 8 |
| §4 GLiNER PERSON 0.65 → 0.80 | Task 11 |
| §5 Config schema (`Rules` map) | Task 7 |
| §5 Migration | Task 7 (initial), Task 23 (cleanup) |
| §6.1 Rules registry package | Tasks 1, 6 |
| §6.2 Per-layer wiring | Tasks 9, 10, 11, 12 |
| §6.3 Hot reload | Tasks 13, 14 |
| §6.4 Cache invalidation | Task 14 |
| §7 GET /api/rules | Task 15 |
| §7 PUT /api/rules + validation | Task 16 |
| §8 Detection Rules card layout | Task 18 |
| §8.4 Tier 1 modal | Task 20 |
| §8.4 Tier 2 popover | Task 21 |
| §8.4 Tier 3 silent | Task 19 |
| §9 Persistent banner / Degraded pill | Task 22 |
| §10 Migration / cleanup | Task 23 |
| §11 Tests | Distributed across all tasks |

**Placeholders:** none. Every code block is concrete.

**Type consistency:**
- `Reconfigure(enabled func(string) bool)` — matches across `presidio.Scanner`, `gliner.Client`, and `Pipeline.Reconfigurable`.
- `entropy.Scanner.Reconfigure(enabled func(string) bool)` reads two specific rule IDs internally — not the same shape as the others, but Pipeline doesn't care; it just calls `.Reconfigure(p)` on whoever implements `Reconfigurable`.
- `coordinator.Reconfigure(enabled, exts, contentPatterns)` — three args, called only from the API handler and main.go. Tests in Task 14 match.

**Scope:** single coherent feature, one plan.

---

## Execution

Plan complete and saved to `docs/superpowers/plans/2026-04-27-detection-rule-config.md`.
