package rules

// catalog and groups together form the canonical list of every detection
// rule and group. Edit this file (and only this file) to add or remove
// rules. Tests in registry_test.go enforce invariants.
//
// Tier data is split into per-tier blocks below. Each tier appends to
// the package-level `catalog` and `groups` slices in init() so that the
// final state is independent of declaration order.

func init() {
	catalog = append(catalog, tier1Rules...)
	groups = append(groups, tier1Groups...)
	catalog = append(catalog, tier2Rules...)
	groups = append(groups, tier2Groups...)
	catalog = append(catalog, tier3Rules...)
	groups = append(groups, tier3Groups...)
}

var tier1Groups = []GroupSpec{
	{ID: "cloud_credentials", Label: "Cloud credentials", Tier: TierAlwaysOn, Rules: []string{"aws_access_key", "aws_secret_key", "gcp_api_key"}},
	{ID: "private_keys", Label: "Private keys", Tier: TierAlwaysOn, Rules: []string{"private_key_pem"}},
	{ID: "auth_tokens", Label: "Auth tokens & secrets", Tier: TierAlwaysOn, Rules: []string{"jwt", "generic_secret_kv", "generic_secret_pwd", "url_with_token"}},
	{ID: "passwords_prose", Label: "Passwords (prose)", Tier: TierAlwaysOn, Rules: []string{"password_prose"}},
	{ID: "connection_strings", Label: "Database connection strings", Tier: TierAlwaysOn, Rules: []string{"connection_string"}},
	{ID: "payment_cards", Label: "Payment cards (full)", Tier: TierAlwaysOn, Rules: []string{"credit_card_luhn", "credit_card_4x4", "credit_card_bare", "cvv"}},
	{ID: "us_ssn", Label: "US Social Security Numbers", Tier: TierAlwaysOn, Rules: []string{"us_ssn_dash", "us_ssn_space"}},
	{ID: "file_blocking", Label: "Sensitive file types (block)", Tier: TierAlwaysOn, Rules: []string{"file_block_env", "file_block_tfstate", "file_block_pem", "file_block_key", "file_block_p12", "file_block_pfx", "file_block_content_patterns"}},
	{ID: "entropy_keyword", Label: "Entropy in secret context", Tier: TierAlwaysOn, Rules: []string{"entropy_keyword_gated"}},
}

var tier1Rules = []RuleSpec{
	// Cloud credentials
	{ID: "aws_access_key", Label: "AWS access key", Describe: `AKIA[0-9A-Z]{16}`, Group: "cloud_credentials", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "aws_secret_key", Label: "AWS secret key", Describe: `aws_secret_access_key=… (40 chars)`, Group: "cloud_credentials", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "gcp_api_key", Label: "GCP API key", Describe: `AIza[0-9A-Za-z\-_]{35}`, Group: "cloud_credentials", Tier: TierAlwaysOn, Layer: "presidio"},

	// Private keys
	{ID: "private_key_pem", Label: "Private key (PEM)", Describe: "PEM blocks: RSA / EC / DSA / OPENSSH", Group: "private_keys", Tier: TierAlwaysOn, Layer: "presidio"},

	// Auth tokens & secrets
	{ID: "jwt", Label: "JWT", Describe: `eyJ…\.eyJ…\.…`, Group: "auth_tokens", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "generic_secret_kv", Label: "Generic key=value secret", Describe: `(password|secret|token|api_key)=… ≥8 chars`, Group: "auth_tokens", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "generic_secret_pwd", Label: "Generic password=value", Describe: `(password|passwd|pwd)=… ≥4 chars (loose)`, Group: "auth_tokens", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "url_with_token", Label: "URL with auth token", Describe: `https://…?token= / ?access_token= / etc.`, Group: "auth_tokens", Tier: TierAlwaysOn, Layer: "presidio"},

	// Passwords (prose)
	{ID: "password_prose", Label: "Password in prose", Describe: `"the password is X"`, Group: "passwords_prose", Tier: TierAlwaysOn, Layer: "presidio"},

	// Connection strings
	{ID: "connection_string", Label: "Database connection string", Describe: `mongodb|postgres|mysql|redis|amqp://…`, Group: "connection_strings", Tier: TierAlwaysOn, Layer: "presidio"},

	// Payment cards
	{ID: "credit_card_luhn", Label: "Credit card (Luhn-validated)", Describe: "Visa/MC/Amex/Discover/Diners with Luhn", Group: "payment_cards", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "credit_card_4x4", Label: "Credit card (4×4 separated)", Describe: `\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b`, Group: "payment_cards", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "credit_card_bare", Label: "Credit card (bare 13–19 digits)", Describe: "13–19 digit unseparated PAN with brand prefix", Group: "payment_cards", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "cvv", Label: "CVV / CVC", Describe: "CVV/CVC keyword + value, near payment-card context", Group: "payment_cards", Tier: TierAlwaysOn, Layer: "presidio"},

	// US SSN
	{ID: "us_ssn_dash", Label: "US SSN (dash-separated)", Describe: `\b\d{3}-\d{2}-\d{4}\b`, Group: "us_ssn", Tier: TierAlwaysOn, Layer: "presidio"},
	{ID: "us_ssn_space", Label: "US SSN (space-separated)", Describe: `\b\d{3}\s\d{2}\s\d{4}\b`, Group: "us_ssn", Tier: TierAlwaysOn, Layer: "presidio"},

	// File blocking
	{ID: "file_block_env", Label: ".env files", Describe: "Block requests containing .env files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
	{ID: "file_block_tfstate", Label: ".tfstate files", Describe: "Block requests containing .tfstate files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
	{ID: "file_block_pem", Label: ".pem files", Describe: "Block requests containing .pem files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
	{ID: "file_block_key", Label: ".key files", Describe: "Block requests containing .key files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
	{ID: "file_block_p12", Label: ".p12 files", Describe: "Block requests containing .p12 files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
	{ID: "file_block_pfx", Label: ".pfx files", Describe: "Block requests containing .pfx files", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},
	{ID: "file_block_content_patterns", Label: "Sensitive content patterns", Describe: "Block on PEM headers / TF state markers", Group: "file_blocking", Tier: TierAlwaysOn, Layer: "fileblock"},

	// Entropy keyword-gated
	{ID: "entropy_keyword_gated", Label: "Entropy near secret keyword", Describe: "Shannon 3.5–4.5 within ±80 chars of password/token/api_key", Group: "entropy_keyword", Tier: TierAlwaysOn, Layer: "entropy"},
}

var tier2Groups = []GroupSpec{
	{ID: "email_addresses", Label: "Email addresses", Tier: TierGoodToHave, Rules: []string{"email_regex", "email_gliner"}},
	{ID: "phone_numbers", Label: "Phone numbers", Tier: TierGoodToHave, Rules: []string{"phone_parens", "phone_dash_dot", "phone_intl_plus", "phone_leading_zero", "phone_double_zero"}},
	{ID: "person_names", Label: "Person names (ML)", Tier: TierGoodToHave, Rules: []string{"person_gliner"}},
	{ID: "physical_addresses", Label: "Physical addresses (ML)", Tier: TierGoodToHave, Rules: []string{"address_gliner"}},
	{ID: "date_of_birth", Label: "Date of birth", Tier: TierGoodToHave, Rules: []string{"dob_mdy", "dob_dmy", "dob_gliner"}},
	{ID: "us_government_ids", Label: "US government IDs", Tier: TierGoodToHave, Rules: []string{"us_passport_alpha", "us_passport_numeric", "us_driver_license", "us_itin_dash", "us_itin_bare"}},
	{ID: "us_bank_accounts", Label: "US bank accounts", Tier: TierGoodToHave, Rules: []string{"us_bank_number", "aba_routing_dashed", "aba_routing_bare"}},
	{ID: "intl_banking", Label: "International banking", Tier: TierGoodToHave, Rules: []string{"iban_presidio", "iban_simple", "swift_bic"}},
	{ID: "cc_expiry", Label: "Credit card expiry", Tier: TierGoodToHave, Rules: []string{"cc_expiry"}},
	{ID: "healthcare_ids", Label: "Healthcare identifiers", Tier: TierGoodToHave, Rules: []string{"dea_license", "us_npi_separated", "us_npi_bare", "us_mbi_separated", "us_mbi_bare", "medical_record_mrn", "health_plan_id"}},
	{ID: "biometric_ids", Label: "Biometric identifiers", Tier: TierGoodToHave, Rules: []string{"biometric_id"}},
	{ID: "insurance_ids", Label: "Insurance / policy IDs", Tier: TierGoodToHave, Rules: []string{"insurance_id"}},
}

var tier2Rules = []RuleSpec{
	{ID: "email_regex", Label: "Email (regex)", Describe: "RFC-shaped local@domain.tld", Group: "email_addresses", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "email_gliner", Label: "Email (ML)", Describe: "GLiNER EMAIL ≥0.70", Group: "email_addresses", Tier: TierGoodToHave, Layer: "gliner"},

	{ID: "phone_parens", Label: "Phone (parens)", Describe: "(415) 555-0136", Group: "phone_numbers", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "phone_dash_dot", Label: "Phone (dash/dot)", Describe: "415-555-0136 / 415.555.0136", Group: "phone_numbers", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "phone_intl_plus", Label: "Phone (international +)", Describe: "+1 415 555 0136", Group: "phone_numbers", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "phone_leading_zero", Label: "Phone (leading zero)", Describe: "0xxx xxxxxx — context-required", Group: "phone_numbers", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "phone_double_zero", Label: "Phone (double zero)", Describe: "00xx xxxxxxxx", Group: "phone_numbers", Tier: TierGoodToHave, Layer: "presidio"},

	{ID: "person_gliner", Label: "Person name (ML)", Describe: "GLiNER PERSON ≥0.80", Group: "person_names", Tier: TierGoodToHave, Layer: "gliner"},
	{ID: "address_gliner", Label: "Address (ML)", Describe: "GLiNER ADDRESS ≥0.75", Group: "physical_addresses", Tier: TierGoodToHave, Layer: "gliner"},

	{ID: "dob_mdy", Label: "DOB MM/DD/YYYY", Describe: "Context-required (born/dob/birthday)", Group: "date_of_birth", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "dob_dmy", Label: "DOB DD/MM/YYYY", Describe: "Context-required (born/dob/birthday)", Group: "date_of_birth", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "dob_gliner", Label: "DOB (ML)", Describe: "GLiNER DATE_OF_BIRTH ≥0.75", Group: "date_of_birth", Tier: TierGoodToHave, Layer: "gliner"},

	{ID: "us_passport_alpha", Label: "US passport (alpha)", Describe: `[A-Z]\d{8}`, Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "us_passport_numeric", Label: "US passport (numeric)", Describe: `\d{9} with passport ctx`, Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "us_driver_license", Label: "US driver license", Describe: "State-shape alternation, context-required", Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "us_itin_dash", Label: "US ITIN (dashed)", Describe: "9XX-7X-XXXX with context", Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "us_itin_bare", Label: "US ITIN (bare)", Describe: "9XX7XXXXX context-required", Group: "us_government_ids", Tier: TierGoodToHave, Layer: "presidio"},

	{ID: "us_bank_number", Label: "US bank account", Describe: "10–17 digits with bank context", Group: "us_bank_accounts", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "aba_routing_dashed", Label: "ABA routing (dashed)", Describe: "XXXX-XXXX-X with checksum", Group: "us_bank_accounts", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "aba_routing_bare", Label: "ABA routing (bare)", Describe: "9 digits, context-required + checksum", Group: "us_bank_accounts", Tier: TierGoodToHave, Layer: "presidio"},

	{ID: "iban_presidio", Label: "IBAN (Presidio)", Describe: "IBAN with mod-97 checksum (context-boosted)", Group: "intl_banking", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "iban_simple", Label: "IBAN (simple)", Describe: "Simpler IBAN shape (context-boosted)", Group: "intl_banking", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "swift_bic", Label: "SWIFT / BIC", Describe: "8/11 alpha SWIFT, context-required", Group: "intl_banking", Tier: TierGoodToHave, Layer: "presidio"},

	{ID: "cc_expiry", Label: "Credit card expiry", Describe: `MM/YY near "card"/"exp"/"valid"`, Group: "cc_expiry", Tier: TierGoodToHave, Layer: "presidio"},

	{ID: "dea_license", Label: "DEA license", Describe: `DEA-shape [A-Z][A-Z]\d{7}`, Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "us_npi_separated", Label: "US NPI (separated)", Describe: "1NNN-NNN-NNN with NPI ctx", Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "us_npi_bare", Label: "US NPI (bare)", Describe: "10-digit NPI, context-required", Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "us_mbi_separated", Label: "US MBI (separated)", Describe: "Medicare MBI hyphenated form", Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "us_mbi_bare", Label: "US MBI (bare)", Describe: "MBI no-separator, context-required", Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "medical_record_mrn", Label: "Medical record (MRN)", Describe: `"MRN: …" / "patient id: …"`, Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "health_plan_id", Label: "Health plan ID", Describe: `"health plan id: …"`, Group: "healthcare_ids", Tier: TierGoodToHave, Layer: "presidio"},

	{ID: "biometric_id", Label: "Biometric identifier", Describe: `"fingerprint hash: …" / "face id: …"`, Group: "biometric_ids", Tier: TierGoodToHave, Layer: "presidio"},
	{ID: "insurance_id", Label: "Insurance / policy ID", Describe: `"policy no: …" / "member id: …"`, Group: "insurance_ids", Tier: TierGoodToHave, Layer: "presidio"},
}

var tier3Groups = []GroupSpec{
	{ID: "ip_addresses", Label: "IP addresses (v4 + v6)", Tier: TierToBeSafer, Rules: []string{"ipv4", "ipv6", "ip_gliner"}},
	{ID: "mac_addresses", Label: "MAC addresses", Tier: TierToBeSafer, Rules: []string{"mac_colon_dash", "mac_cisco_dot"}},
	{ID: "bare_urls", Label: "Bare URLs", Tier: TierToBeSafer, Rules: []string{"url_bare"}},
	{ID: "crypto_wallets", Label: "Crypto wallet addresses", Tier: TierToBeSafer, Rules: []string{"crypto_btc", "crypto_eth"}},
	{ID: "uk_ids", Label: "UK identifiers", Tier: TierToBeSafer, Rules: []string{"uk_nhs", "uk_nino", "uk_postcode", "uk_passport", "uk_driving_licence"}},
	{ID: "ca_sin", Label: "Canada — SIN", Tier: TierToBeSafer, Rules: []string{"ca_sin"}},
	{ID: "au_tfn", Label: "Australia — TFN", Tier: TierToBeSafer, Rules: []string{"au_tfn"}},
	{ID: "in_pan", Label: "India — PAN", Tier: TierToBeSafer, Rules: []string{"in_pan"}},
	{ID: "es_nif", Label: "Spain — NIF", Tier: TierToBeSafer, Rules: []string{"es_nif"}},
	{ID: "de_passport", Label: "Germany — Passport", Tier: TierToBeSafer, Rules: []string{"de_passport"}},
	{ID: "sg_nric_fin", Label: "Singapore — NRIC/FIN", Tier: TierToBeSafer, Rules: []string{"sg_nric_fin"}},
	{ID: "license_plates", Label: "License plates", Tier: TierToBeSafer, Rules: []string{"license_plate"}},
	{ID: "device_ids", Label: "Device identifiers (IMEI)", Tier: TierToBeSafer, Rules: []string{"imei"}},
	{ID: "generic_system_ids", Label: "Generic system IDs", Tier: TierToBeSafer, Rules: []string{"person_id_generic", "registration_id_generic"}},
	{ID: "entropy_unconditional", Label: "Entropy unconditional", Tier: TierToBeSafer, Rules: []string{"entropy_unconditional"}},
	{ID: "ml_duplicates", Label: "ML duplicates", Tier: TierToBeSafer, Rules: []string{"gliner_email_dup", "gliner_ip_dup", "gliner_national_id_dup", "gliner_person_dup"}},
}

var tier3Rules = []RuleSpec{
	{ID: "ipv4", Label: "IPv4", Describe: "Dotted-quad IPv4", Group: "ip_addresses", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "ipv6", Label: "IPv6", Describe: "Full + compressed IPv6", Group: "ip_addresses", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "ip_gliner", Label: "IP (ML)", Describe: "GLiNER IP ≥0.75 (post-filtered)", Group: "ip_addresses", Tier: TierToBeSafer, Layer: "gliner"},

	{ID: "mac_colon_dash", Label: "MAC (colon/dash)", Describe: "aa:bb:cc:dd:ee:ff / aa-bb-…", Group: "mac_addresses", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "mac_cisco_dot", Label: "MAC (Cisco dot)", Describe: "aaaa.bbbb.cccc", Group: "mac_addresses", Tier: TierToBeSafer, Layer: "presidio"},

	{ID: "url_bare", Label: "Bare URL", Describe: "Any http(s)://… (with skiplist)", Group: "bare_urls", Tier: TierToBeSafer, Layer: "presidio"},

	{ID: "crypto_btc", Label: "Bitcoin address", Describe: "bc1… / [13]…", Group: "crypto_wallets", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "crypto_eth", Label: "Ethereum address", Describe: `0x[a-f0-9]{40}`, Group: "crypto_wallets", Tier: TierToBeSafer, Layer: "presidio"},

	{ID: "uk_nhs", Label: "UK NHS number", Describe: "NHS number (mod-11)", Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "uk_nino", Label: "UK NINO", Describe: "National Insurance Number", Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "uk_postcode", Label: "UK postcode", Describe: "UK postcode", Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "uk_passport", Label: "UK passport", Describe: `[A-Z]{2}\d{7} with ctx`, Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "uk_driving_licence", Label: "UK driving licence", Describe: "DVLA driving licence shape", Group: "uk_ids", Tier: TierToBeSafer, Layer: "presidio"},

	{ID: "ca_sin", Label: "Canada SIN", Describe: "[1-79]NN-NNN-NNN Luhn", Group: "ca_sin", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "au_tfn", Label: "Australia TFN", Describe: "NNN NNN NNN mod-11", Group: "au_tfn", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "in_pan", Label: "India PAN", Describe: "10-char PAN format", Group: "in_pan", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "es_nif", Label: "Spain NIF", Describe: "8 digits + check letter", Group: "es_nif", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "de_passport", Label: "Germany passport", Describe: "German passport with German keywords", Group: "de_passport", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "sg_nric_fin", Label: "Singapore NRIC/FIN", Describe: `[STFGM]\d{7}[A-Z]`, Group: "sg_nric_fin", Tier: TierToBeSafer, Layer: "presidio"},

	{ID: "license_plate", Label: "License plate", Describe: `"license plate: …" / "VRN: …"`, Group: "license_plates", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "imei", Label: "IMEI", Describe: "NN-NNNNNN-NNNNNN-N", Group: "device_ids", Tier: TierToBeSafer, Layer: "presidio"},

	{ID: "person_id_generic", Label: "Generic person/customer/order ID", Describe: `"customer/employee/order/ticket id: …"`, Group: "generic_system_ids", Tier: TierToBeSafer, Layer: "presidio"},
	{ID: "registration_id_generic", Label: "Registration / enrollment ID", Describe: `"student/registration/enrollment no: …"`, Group: "generic_system_ids", Tier: TierToBeSafer, Layer: "presidio"},

	{ID: "entropy_unconditional", Label: "High-entropy strings (unconditional)", Describe: "Shannon ≥4.5 firing without keyword context", Group: "entropy_unconditional", Tier: TierToBeSafer, Layer: "entropy"},

	{ID: "gliner_email_dup", Label: "ML email (duplicate)", Describe: "GLiNER EMAIL — already covered by email_regex", Group: "ml_duplicates", Tier: TierToBeSafer, Layer: "gliner"},
	{ID: "gliner_ip_dup", Label: "ML IP (duplicate)", Describe: "GLiNER IP — already covered by ipv4", Group: "ml_duplicates", Tier: TierToBeSafer, Layer: "gliner"},
	{ID: "gliner_national_id_dup", Label: "ML NATIONAL_ID", Describe: "GLiNER NATIONAL_ID — vague label, mostly redundant", Group: "ml_duplicates", Tier: TierToBeSafer, Layer: "gliner"},
	{ID: "gliner_person_dup", Label: "ML person (duplicate)", Describe: "GLiNER PERSON — already covered by person_gliner in Tier 2", Group: "ml_duplicates", Tier: TierToBeSafer, Layer: "gliner"},
}
