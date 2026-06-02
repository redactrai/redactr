# Detection Rule Configuration — Design

**Status:** Approved for implementation planning
**Author:** Redactr team (brainstormed 2026-04-27)
**Scope:** Make every detection rule individually toggleable from the dashboard, organised into a tiered group hierarchy, with warning UX scaled to the risk of disabling each rule.

---

## 1. Problem

Today's pipeline (presidio + entropy + gliner + contextgate) compiles ~70 hard-coded patterns across four layers. The user has only three coarse switches: `regex_enabled`, `entropy_enabled`, `gliner_enabled`. There is no way to disable a single noisy rule without disabling its entire layer.

This produces two failure modes:

1. **False-positive flood.** Bare URL matches, IPv4 in test fixtures, UUIDs flagged by unconditional entropy, ML PERSON detection on capitalized prose words.
2. **All-or-nothing layers.** A user who only wants secret detection (no PII) cannot turn off email/phone/name without also disabling AWS-key detection.

We need fine-grained rule control plus group-level convenience, with disabling-the-important-things being deliberately friction-ful.

---

## 2. Goals & non-goals

**Goals**
- Each individual detection rule is independently toggleable.
- Rules are organised into 37 named groups across 3 tiers (Always On / Good to Have / To Be Safer).
- Group toggle acts as select-all / select-none for its members; group state is computed from members and can be indeterminate.
- Disabling actions trigger warnings scaled to the rule's tier, regardless of whether the user toggles individually or via the group.
- Defaults are sensible for a developer using AI coding tools: Tier 1 + Tier 2 on, Tier 3 off.
- New rules added in future code releases default to their tier's default-on/off without requiring config migrations.

**Non-goals**
- No per-rule confidence threshold tuning from the UI (e.g. GLiNER PERSON ≥0.65 → 0.80 is hard-coded as part of this work, not user-configurable).
- No custom rule authoring through the UI (existing `custom_patterns` config remains as-is).
- No tier override (a user cannot promote a Tier 3 rule to Tier 1 to get the louder warning).
- No per-domain or per-provider rule selection (rules apply to all intercepted traffic uniformly).
- No mobile/responsive considerations beyond what already exists.

---

## 3. The 37 groups, 85 rules

### Tier 1 — Always On *(default ON, modal + persistent banner on disable)*

| Group ID | Group label | Rule IDs | Notes |
|---|---|---|---|
| `cloud_credentials` | Cloud credentials | `aws_access_key`, `aws_secret_key`, `gcp_api_key` | |
| `private_keys` | Private keys | `private_key_pem` | single-rule |
| `auth_tokens` | Auth tokens & secrets | `jwt`, `generic_secret_kv`, `generic_secret_pwd`, `url_with_token` | |
| `passwords_prose` | Passwords (prose) | `password_prose` | single-rule |
| `connection_strings` | Database connection strings | `connection_string` | single-rule |
| `payment_cards` | Payment cards (full) | `credit_card_luhn`, `credit_card_4x4`, `credit_card_bare`, `cvv` | CVV tightened: see §4 |
| `us_ssn` | US Social Security Numbers | `us_ssn_dash`, `us_ssn_space` | |
| `file_blocking` | Sensitive file types (block) | `file_block_env`, `file_block_tfstate`, `file_block_pem`, `file_block_key`, `file_block_p12`, `file_block_pfx`, `file_block_content_patterns` | wires existing file-blocking stage |
| `entropy_keyword` | Entropy in secret context | `entropy_keyword_gated` | single-rule (Shannon 3.5–4.5 with keyword ±80) |

**Total: 9 groups, 24 rules.**

### Tier 2 — Good to Have *(default ON, inline confirm popover on disable)*

| Group ID | Group label | Rule IDs |
|---|---|---|
| `email_addresses` | Email addresses | `email_regex`, `email_gliner` |
| `phone_numbers` | Phone numbers | `phone_parens`, `phone_dash_dot`, `phone_intl_plus`, `phone_leading_zero`, `phone_double_zero` |
| `person_names` | Person names (ML) | `person_gliner` *(threshold raised 0.65 → 0.80)* |
| `physical_addresses` | Physical addresses (ML) | `address_gliner` |
| `date_of_birth` | Date of birth | `dob_mdy`, `dob_dmy`, `dob_gliner` |
| `us_government_ids` | US government IDs | `us_passport_alpha`, `us_passport_numeric`, `us_driver_license`, `us_itin_dash`, `us_itin_bare` |
| `us_bank_accounts` | US bank accounts | `us_bank_number`, `aba_routing_dashed`, `aba_routing_bare` |
| `intl_banking` | International banking | `iban_presidio`, `iban_simple`, `swift_bic` |
| `cc_expiry` | Credit card expiry | `cc_expiry` |
| `healthcare_ids` | Healthcare identifiers | `dea_license`, `us_npi_separated`, `us_npi_bare`, `us_mbi_separated`, `us_mbi_bare`, `medical_record_mrn`, `health_plan_id` |
| `biometric_ids` | Biometric identifiers | `biometric_id` |
| `insurance_ids` | Insurance / policy IDs | `insurance_id` |

**Total: 12 groups, 33 rules.**

### Tier 3 — To Be Safer *(default OFF, silent toggle in either direction)*

| Group ID | Group label | Rule IDs |
|---|---|---|
| `ip_addresses` | IP addresses (v4 + v6) | `ipv4`, `ipv6`, `ip_gliner` |
| `mac_addresses` | MAC addresses | `mac_colon_dash`, `mac_cisco_dot` |
| `bare_urls` | Bare URLs | `url_bare` |
| `crypto_wallets` | Crypto wallet addresses | `crypto_btc`, `crypto_eth` |
| `uk_ids` | UK identifiers | `uk_nhs`, `uk_nino`, `uk_postcode`, `uk_passport`, `uk_driving_licence` |
| `ca_sin` | Canada — SIN | `ca_sin` |
| `au_tfn` | Australia — TFN | `au_tfn` |
| `in_pan` | India — PAN | `in_pan` |
| `es_nif` | Spain — NIF | `es_nif` |
| `de_passport` | Germany — Passport | `de_passport` |
| `sg_nric_fin` | Singapore — NRIC/FIN | `sg_nric_fin` |
| `license_plates` | License plates | `license_plate` |
| `device_ids` | Device identifiers (IMEI) | `imei` |
| `generic_system_ids` | Generic system IDs | `person_id_generic`, `registration_id_generic` |
| `entropy_unconditional` | Entropy unconditional | `entropy_unconditional` |
| `ml_duplicates` | ML duplicates | `gliner_email_dup`, `gliner_ip_dup`, `gliner_national_id_dup` |

**Total: 16 groups, 28 rules.**

### Grand totals
- **37 groups**, **85 individual rules**
- 24 rules in Tier 1, 33 in Tier 2, 28 in Tier 3
- 9 groups are single-rule

**Invariant:** every rule in a group shares that group's tier. There are no mixed-tier groups. This means the warning level for a group toggle is unambiguous — it's the group's tier.

---

## 4. Rule-level changes folded into this work

These are not just configuration changes — the underlying rules are modified as part of this rewrite:

1. **`cvv` (Tier 1)** — currently fires on `cvv: 123` in any context. Tighten to require *both* the existing keyword prefix *and* nearby payment-card context (`card`, `credit`, `visa`, `mastercard`, `amex`, `expir`, `cardholder`, `payment`) within ±100 chars. `contextReq: true`.
2. **`person_gliner` (Tier 2)** — raise per-label confidence threshold from `0.65` → `0.80` in `gliner.Client.labelMinConfidence`.

No other rule logic is altered. All other changes are pure configuration plumbing.

---

## 5. Configuration schema

Extend `internal/config/config.go`:

```go
type ScanningConfig struct {
    // ... existing fields kept as-is for backwards compatibility ...

    // Rules holds the user's per-rule toggle state. Keys are the rule IDs
    // listed in §3. Missing keys fall back to their tier's default
    // (Tier 1 + 2 default on, Tier 3 default off).
    Rules map[string]bool `yaml:"rules"`
}
```

**Persistence semantics**
- Stored at `~/.redactr/config.yaml` under `scanning.rules`.
- Backwards compatible: existing configs without a `rules` map work unchanged — every rule defaults to its tier's default.
- The map only stores *deviations* from defaults. When a rule's value matches its default, the API returns it but config-save can omit it. (See §7 for the API contract.)
- Forward compatible: rule IDs added in future releases are unknown to old configs; they appear with their defaults.

**Validation**
- Unknown rule IDs in incoming `PUT /api/rules` are rejected with `400` and a list of the bad keys.
- The `enabled_layers` derived state (presidio/entropy/gliner) is computed from rule states: a layer with all rules disabled is skipped at scan time.

---

## 6. Backend architecture

### 6.1 New package: `internal/scanner/rules`

A central registry mapping every rule ID to its tier, group, default, and a builder function that returns the underlying compiled pattern (or layer-specific config).

```go
package rules

type Tier int
const (
    TierAlwaysOn Tier = iota + 1
    TierGoodToHave
    TierToBeSafer
)

type RuleSpec struct {
    ID         string  // stable config key, e.g. "aws_access_key"
    Group      string  // group ID, e.g. "cloud_credentials"
    Label      string  // human label for UI
    Tier       Tier
    DefaultOn  bool    // derived from Tier in practice; explicit for clarity
    Layer      string  // "presidio" | "entropy" | "gliner" | "fileblock"
    Describe   string  // one-line explanation for UI tooltip/disclosure
}

type GroupSpec struct {
    ID    string
    Label string
    Tier  Tier
    Rules []string // ordered rule IDs
}

func AllRules()  []RuleSpec
func AllGroups() []GroupSpec
func ResolveDefault(id string) bool   // tier default
func IsKnown(id string) bool
```

This is the **single source of truth** for rule metadata. The Presidio scanner, the Entropy scanner, the GLiNER client, the file-blocking stage, and the API handler all consult this registry.

### 6.2 Per-layer wiring

- **Presidio (`internal/scanner/presidio/presidio.go`)** — currently `build()` appends every pattern unconditionally. Change `New(...)` to accept `func(ruleID string) bool` (an `isEnabled` predicate) and skip patterns whose rule ID is disabled. Each pattern in `defs[]` gets a `ruleID` field added; existing labels (`AWS_ACCESS_KEY`, `EMAIL_ADDRESS`, etc.) map to rule IDs (lowercased + snake-cased; explicit mapping table in `rules` package).
- **Entropy (`internal/scanner/entropy/entropy.go`)** — `Scanner` gets two booleans: `keywordGated` (Tier 1 rule `entropy_keyword_gated`) and `unconditional` (Tier 3 rule `entropy_unconditional`). The scan logic branches on these instead of the current hard-coded behaviour.
- **GLiNER (`internal/scanner/gliner/client.go`)** — current `suppressLabels` set becomes dynamic: built from the rule registry, suppressing labels whose corresponding rule is disabled. Per-label confidence map stays hard-coded.
- **File blocking (`internal/fileblock/`)** — per-extension rules pull their values from `scanning.rules.file_block_<ext>`; the existing `blocked_extensions` list in config stays as the source for *additional* user-defined extensions, but the default six (`.env`, `.tfstate`, `.pem`, `.key`, `.p12`, `.pfx`) are individually toggleable through the rule map.

### 6.3 Hot-reload

Today, scanners are constructed once at process startup with the initial config. Rule toggles need to take effect on `PUT /api/rules` without restarting the daemon.

**Approach:** each scanner gains a `Reconfigure(cfg ScanningConfig)` method. The API handler calls `coordinator.Reconfigure(cfg)` after persisting new rules; the coordinator forwards to each layer. Reconfigure is concurrency-safe — scanners hold an `atomic.Pointer` to their compiled pattern set and swap it atomically.

### 6.4 Cache invalidation

Toggling a rule changes scan results, so the existing scan cache (`internal/scanner/cache.go`) must be invalidated on `Reconfigure`. The coordinator's `InvalidateCache()` is already wired and is called as part of the reconfigure path.

---

## 7. API surface

### `GET /api/rules`

Returns the full catalogue plus current state. UI uses this to render.

```json
{
  "tiers": [
    {
      "id": "always_on",
      "label": "Always On",
      "default": true,
      "warning_level": "modal_and_banner"
    },
    { "id": "good_to_have",  "label": "Good to Have",  "default": true,  "warning_level": "inline_confirm" },
    { "id": "to_be_safer",   "label": "To Be Safer",   "default": false, "warning_level": "silent" }
  ],
  "groups": [
    {
      "id": "cloud_credentials",
      "label": "Cloud credentials",
      "tier": "always_on",
      "rules": ["aws_access_key", "aws_secret_key", "gcp_api_key"]
    },
    /* ... 36 more ... */
  ],
  "rules": [
    {
      "id": "aws_access_key",
      "label": "AWS access key",
      "describe": "AKIA[0-9A-Z]{16}",
      "group": "cloud_credentials",
      "tier": "always_on",
      "layer": "presidio",
      "default": true,
      "enabled": true
    },
    /* ... 84 more ... */
  ]
}
```

### `PUT /api/rules`

Accepts a sparse map of rule IDs to booleans. Only changed-from-default keys need to be sent; the server stores the full map but normalises to drop any key that equals its tier default.

```json
{ "rules": { "aws_access_key": false, "ipv4": true } }
```

**Response codes**
- `200` — normalised map persisted.
- `400` — unknown rule IDs (returned as `{"error": "unknown rule_ids", "rule_ids": [...]}`)
- `500` — config write failed; previous state remains in memory and on disk.

### Behaviour of legacy `PUT /api/config`

The existing `PUT /api/config` endpoint preserves the `scanning.rules` map verbatim (does not overwrite or clear). Old clients that don't know about rules can still update other config fields without losing rule state.

---

## 8. UI design

### 8.1 Where it lives

A new card titled **"Detection rules"** in the existing **Configuration** tab, placed first (above the existing Scanning Layers card, which becomes redundant and is removed in this rewrite — its three booleans are subsumed by the rule toggles).

### 8.2 Layout

The card contains three collapsible sections, one per tier:

```
┌─ Detection rules ──────────────────────────────────────────────┐
│                                                                  │
│  ▾ Always On  ·  9 / 9 groups enabled  ·  24 rules                │
│    ┌─ Cloud credentials                              [✓] toggle │
│    │  ▸ Show 3 rules                                             │
│    └─ Private keys                                  [✓] toggle │
│       (single rule — no disclosure)                              │
│    ...                                                           │
│                                                                  │
│  ▾ Good to Have  ·  10 / 12 groups enabled  ·  29 rules           │
│    ...                                                           │
│                                                                  │
│  ▸ To Be Safer  ·  2 / 16 groups enabled  ·  4 rules              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

- Each tier has a header summarising group count and active rule count.
- Each row inside a tier is a **group**: a toggle, a label, and a "Show N rules" disclosure for multi-rule groups.
- Single-rule groups show the toggle without disclosure.
- Expanding the disclosure reveals an indented list of individual rule rows, each with its own toggle + the rule's regex/heuristic description as helper text.

### 8.3 Toggle visual states

- `✓` solid green — fully enabled.
- `–` half-filled — indeterminate (group only).
- `✗` empty — fully disabled.

### 8.4 Warning behaviour

The warning level depends on the tier of the rule(s) being affected by the action, not on whether the user clicked group or individual.

**Tier 1 — Always On**

When the user attempts to disable a Tier 1 rule (individual or via group):

1. **Flip-time modal** — captures intent before the change applies.
   - Title: "Disable a critical detection rule?"
   - Body: lists every Tier 1 rule about to be disabled, with one-line description each.
   - Body: red banner — "Disabling this means matching credentials/PII will be sent to the AI provider unredacted."
   - Buttons: **Cancel** (default), **Disable anyway**.
2. **Persistent Overview banner** — once any Tier 1 rule is off:
   - Yellow banner on the Overview hero card.
   - Text: "N best-practice rules disabled: <comma-separated rule labels>. <a href="#config">Review</a>."
   - Stays until all Tier 1 rules are re-enabled.

**Tier 2 — Good to Have**

When the user attempts to disable a Tier 2 rule:

1. **Inline confirmation popover** anchored to the toggle.
   - Text: "Disable <rule label>?"
   - Buttons: **Cancel**, **Disable**.
   - No persistent banner.

**Tier 3 — To Be Safer**

Both directions silent. No popover, no banner. Toggle flips immediately.

### 8.5 Group-level toggles

Clicking a group toggle:
- If group is fully on → confirms at the group's tier (Tier 1 = modal, Tier 2 = inline popover, Tier 3 = silent) and disables all members.
- If group is off or indeterminate → enables all members. No confirmation in the on-direction.

The modal/popover for a group disable lists **every member rule** that will be disabled, so the user sees the full impact.

### 8.6 Wiring

- Initial render fetches `GET /api/rules`, builds the three sections.
- Toggle changes are batched until the user clicks **Save configuration** at the bottom of the Configuration tab (consistent with existing config save flow). No optimistic save.
- The save submits a single `PUT /api/rules` with all changes.
- A single failed save does not partially apply; the server is the authority and the UI re-fetches on error.

### 8.7 Empty-search visibility

A search box at the top of the card filters by rule ID, label, or description. Useful for finding "where is the AWS rule" in 85 entries.

---

## 9. Behaviour at boundaries

- **All Tier 1 rules disabled.** The Overview banner becomes red instead of yellow, and the proxy status pill in the topbar shows a "Degraded protection" subtitle. Proxy still routes traffic.
- **All rules in a layer disabled.** That layer is skipped at scan time (zero overhead); coordinator's reported `LayerResults` includes a row with `findings_count: 0` and `latency_ms: 0` so the UI can still show layer status.
- **All scanning rules disabled (everything off).** A single confirmation step on the Configuration tab "Save" warns: "No detection rules are enabled. The proxy will forward all traffic unredacted." File-blocking rules (Tier 1 group #8) are independent of scanning and stay in effect unless also disabled.
- **Custom user-defined patterns** (existing `scanning.custom_patterns`) are unaffected — they always run if any of them is defined.

---

## 10. Migration & backwards compatibility

- The legacy `regex_enabled`, `entropy_enabled`, `gliner_enabled` config fields are **removed** from the YAML schema (with a one-time migration on first load by the new daemon: if any of the three is `false`, every rule belonging to that layer is written as `false` in the new `rules` map).
- The legacy "Scanning Layers" card in the Configuration tab is removed; its function is fully subsumed by the new card.
- The `Custom patterns` and `Custom blocked words` config fields stay as-is — they remain layer-level concepts.

---

## 11. Testing strategy

- **Unit: rules registry.** `TestAllRulesHaveGroup`, `TestNoOrphanGroups`, `TestEveryRuleHasUniqueID`, `TestTierDefaultsConsistent`.
- **Unit: per-layer toggle wiring.** For each layer, a table-driven test confirms that a disabled rule produces zero findings of that label, and an enabled rule produces ≥1 finding on a known-positive input.
- **Unit: hot reload.** Construct a coordinator, scan, disable a rule via `Reconfigure`, scan the same input, assert finding disappears. Re-enable, assert it reappears.
- **Unit: validation.** `PUT /api/rules` with unknown IDs returns `400`. `PUT` with mixed-known-unknown rejects the whole request (atomic).
- **Unit: defaults.** A config with no `rules` map produces the same behaviour as a config with all defaults explicitly set.
- **Integration: existing API tests stay green** (they don't touch `rules` and shouldn't break).
- **Integration: dashboard render.** A new test for `GET /api/rules` schema, asserting all 37 groups and all 85 rules appear.
- **Integration: warning UX.** Manual / Playwright test for the modal-on-Tier-1-disable flow. (Marked as deferred; not part of MVP.)

---

## 12. Out of scope (deferred)

- Custom user rules editable from UI (still requires direct config-file edit).
- Per-domain rule selection.
- Tier override.
- Scheduled/temporary disable ("disable for 1 hour").
- Audit log of who disabled what when.
- Confidence threshold sliders for ML labels.

---

## 13. Open questions

None at design-approval time. Implementation plan should answer:
- Whether the `rules` package lives at `internal/scanner/rules/` or `internal/rules/` (lean toward the latter — file-blocking is not a scanner).
- Whether the inline confirm popover for Tier 2 reuses the toast component or is a new primitive.
