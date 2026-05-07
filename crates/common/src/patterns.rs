use regex::Regex;
use std::sync::OnceLock;

pub const COLUMN_DENYLIST: &[&str] = &[
    "email",
    "ssn",
    "dob",
    "phone",
    "npi",
    "credit_card",
    "card_number",
    "cvv",
    "passport",
    "license_number",
    "full_name",
    "first_name",
    "last_name",
    "surname",
    "birthdate",
    "salutation",
];

pub struct BuiltinPattern {
    pub name: &'static str,
    pub regex: &'static str,
    pub confidence: f32,
}

pub const BUILTIN_PATTERNS: &[BuiltinPattern] = &[
    BuiltinPattern {
        name: "email",
        regex: r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b",
        confidence: 0.95,
    },
    BuiltinPattern {
        name: "ssn",
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
        confidence: 0.90,
    },
    BuiltinPattern {
        name: "phone",
        regex: r"\b(\+?1[\s.-]?)?\(?\d{3}\)?(?:[\s.\-]\d{3}[\s.\-]\d{4}|\d{7})\b",
        confidence: 0.70,
    },
    BuiltinPattern {
        name: "credit_card",
        regex: r"\b\d{13,16}\b",
        confidence: 0.65,
    },
];

/// Token-to-PII-type synonym table. Entries labelled "bigram" are matched by joining
/// consecutive token pairs (e.g. "first"+"name" → "firstname"), not as bare tokens.
/// First match wins; table order is the tie-breaker.
const TOKEN_SYNONYMS: &[(&str, &str)] = &[
    ("email", "email"),
    ("mail", "email"),
    ("phone", "phone"),
    ("mobile", "phone"),
    ("tel", "phone"),
    ("fax", "phone"),
    ("ssn", "ssn"),
    ("dob", "dob"),
    ("birth", "dob"),
    ("birthday", "dob"),
    ("birthdate", "dob"),
    ("card", "credit_card"),
    ("cvv", "cvv"),
    ("cvc", "cvv"),
    ("passport", "passport"),
    ("npi", "npi"),
    ("license", "license"),
    ("ip", "ip"),
    ("salutation", "salutation"),
    ("surname", "name"),
    // Bigram entries: matched via consecutive token pairs joined without separator.
    // "product_name" → ["product","name"] → bigram "productname" → no match (safe).
    // "first_name"   → ["first","name"]   → bigram "firstname"   → match.
    ("firstname", "name"),
    ("firstnames", "name"),
    ("lastname", "name"),
    ("lastnames", "name"),
    ("fullname", "name"),
    ("givenname", "name"),
    ("givennames", "name"),
    ("familyname", "name"),
    ("familynames", "name"),
];

/// Split `name` into lowercase tokens, handling underscore/hyphen separators and camelCase.
///
/// "userEmail"    → ["user", "email"]
/// "email_address"→ ["email", "address"]
/// "SSNField"     → ["ssn", "field"]
/// "dateOfBirth"  → ["date", "of", "birth"]
fn tokenize_column(name: &str) -> Vec<String> {
    static CAMEL1: OnceLock<Regex> = OnceLock::new();
    static CAMEL2: OnceLock<Regex> = OnceLock::new();
    // Insert a space at lowercase→UPPERCASE transitions: "userEmail" → "user Email"
    let re1 = CAMEL1.get_or_init(|| Regex::new(r"([a-z])([A-Z])").unwrap());
    // Insert a space before the last uppercase in an acronym run: "SSNField" → "SSN Field"
    let re2 = CAMEL2.get_or_init(|| Regex::new(r"([A-Z]+)([A-Z][a-z])").unwrap());
    let spaced = re1.replace_all(name, "${1} ${2}");
    let spaced = re2.replace_all(&spaced, "${1} ${2}");
    spaced
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
}

/// Person-entity prefixes: `<prefix>_name` / `<prefix>_names` → "name".
/// Deliberately excludes generic prefixes like "account", "vendor", "company"
/// that more often refer to non-person entities.
const NAME_PREFIXES: &[&str] = &[
    "contact",
    "person",
    "customer",
    "client",
    "employee",
    "member",
    "patient",
    "owner",
    "recipient",
    "sender",
];

/// Returns the PII type label if any token (or consecutive token bigram) of `column_name`
/// matches a sensitive synonym. First match in `TOKEN_SYNONYMS` wins.
///
/// Avoids over-broad "name" matching: "product_name" → `None`; "first_name" → `Some("name")`.
pub fn classify_column(column_name: &str) -> Option<&'static str> {
    let tokens = tokenize_column(column_name);
    // Single-token pass
    for token in &tokens {
        if let Some(&(_, pii_type)) = TOKEN_SYNONYMS.iter().find(|(t, _)| *t == token.as_str()) {
            return Some(pii_type);
        }
    }
    // Bigram pass: join each consecutive pair and check
    for pair in tokens.windows(2) {
        let bigram = format!("{}{}", pair[0], pair[1]);
        if let Some(&(_, pii_type)) = TOKEN_SYNONYMS.iter().find(|(t, _)| *t == bigram.as_str()) {
            return Some(pii_type);
        }
    }
    // Prefix-name pass: <person-prefix> + "name"/"names" → "name"
    for pair in tokens.windows(2) {
        if NAME_PREFIXES.contains(&pair[0].as_str()) && (pair[1] == "name" || pair[1] == "names") {
            return Some("name");
        }
    }
    None
}

pub struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
    pub confidence: f32,
}

impl CompiledPattern {
    pub fn from_builtins() -> Vec<Self> {
        BUILTIN_PATTERNS
            .iter()
            .map(|p| CompiledPattern {
                name: p.name.to_string(),
                regex: Regex::new(p.regex).expect("builtin regex is valid"),
                confidence: p.confidence,
            })
            .collect()
    }

    /// Build compiled patterns from builtins, overlaying any user-supplied overrides.
    /// Same-named user patterns replace the builtin; new names are appended.
    pub fn from_config(
        user_patterns: &std::collections::HashMap<String, crate::config::Pattern>,
    ) -> Vec<Self> {
        let mut patterns = Self::from_builtins();
        for (name, user_pat) in user_patterns {
            let regex = match Regex::new(&user_pat.regex) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Some(existing) = patterns.iter_mut().find(|p| &p.name == name) {
                existing.regex = regex;
                existing.confidence = user_pat.confidence;
            } else {
                patterns.push(CompiledPattern {
                    name: name.clone(),
                    regex,
                    confidence: user_pat.confidence,
                });
            }
        }
        patterns
    }
}

pub struct Luhn;

impl Luhn {
    /// Returns true if the string passes the Luhn check and has 13–19 digits.
    pub fn check(s: &str) -> bool {
        let digits: Vec<u32> = s
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }
        let sum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &d)| {
                if i % 2 == 1 {
                    let v = d * 2;
                    if v > 9 {
                        v - 9
                    } else {
                        v
                    }
                } else {
                    d
                }
            })
            .sum();
        sum.is_multiple_of(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(name: &str) -> CompiledPattern {
        CompiledPattern::from_builtins()
            .into_iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("builtin pattern '{}' not found", name))
    }

    // --- CompiledPattern::from_builtins ---

    #[test]
    fn all_four_builtins_present() {
        let patterns = CompiledPattern::from_builtins();
        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        for expected in &["email", "ssn", "phone", "credit_card"] {
            assert!(names.contains(expected), "missing builtin: {}", expected);
        }
        assert_eq!(patterns.len(), 4);
    }

    #[test]
    fn builtin_confidences_in_range() {
        for p in CompiledPattern::from_builtins() {
            assert!(
                p.confidence > 0.0 && p.confidence <= 1.0,
                "{}: confidence {} out of range",
                p.name,
                p.confidence
            );
        }
    }

    // --- Column denylist ---

    #[test]
    fn denylist_contains_required_entries() {
        let required = [
            "email",
            "ssn",
            "dob",
            "phone",
            "npi",
            "credit_card",
            "card_number",
            "cvv",
            "passport",
            "license_number",
            "full_name",
            "first_name",
            "last_name",
            "surname",
            "birthdate",
            "salutation",
        ];
        for entry in &required {
            assert!(
                COLUMN_DENYLIST.contains(entry),
                "missing denylist entry: {}",
                entry
            );
        }
    }

    // --- Email ---

    #[test]
    fn email_matches_golden_corpus() {
        let p = pattern("email");
        for addr in &[
            "user@example.com",
            "john.doe+tag@company.co.uk",
            "admin@sub.domain.org",
            "test123@mail.io",
            "UPPER@EXAMPLE.COM",
        ] {
            assert!(p.regex.is_match(addr), "expected email match: {}", addr);
        }
    }

    #[test]
    fn email_rejects_negatives() {
        let p = pattern("email");
        for s in &["notanemail", "missing-at-sign.com", "two@@ats.com"] {
            assert!(!p.regex.is_match(s), "unexpected email match: {}", s);
        }
    }

    // --- SSN ---

    #[test]
    fn ssn_matches_golden_corpus() {
        let p = pattern("ssn");
        for ssn in &["123-45-6789", "987-65-4321", "000-12-3456"] {
            assert!(p.regex.is_match(ssn), "expected SSN match: {}", ssn);
        }
    }

    #[test]
    fn ssn_rejects_negatives() {
        let p = pattern("ssn");
        for s in &[
            "123456789",   // no dashes
            "12-345-6789", // wrong grouping
            "1234-56-789", // wrong grouping
        ] {
            assert!(!p.regex.is_match(s), "unexpected SSN match: {}", s);
        }
    }

    // --- Phone ---

    #[test]
    fn phone_matches_golden_corpus() {
        let p = pattern("phone");
        for num in &[
            "555-123-4567",
            "(555) 123-4567",
            "+1 555-123-4567",
            "555.123.4567",
            "5551234567",
        ] {
            assert!(p.regex.is_match(num), "expected phone match: {}", num);
        }
    }

    #[test]
    fn phone_rejects_negatives() {
        let p = pattern("phone");
        for s in &["hello world", "not a number", "12345"] {
            assert!(!p.regex.is_match(s), "unexpected phone match: {}", s);
        }
    }

    // --- Credit card regex ---

    #[test]
    fn credit_card_regex_matches_13_to_16_digit_strings() {
        let p = pattern("credit_card");
        for s in &[
            "4532015112830366", // 16 digits
            "4111111111111111", // 16 digits
            "5500005555555559", // 16 digits
            "1234567890123",    // 13 digits
        ] {
            assert!(
                p.regex.is_match(s),
                "expected credit_card regex match: {}",
                s
            );
        }
    }

    #[test]
    fn credit_card_regex_rejects_too_few_digits() {
        let p = pattern("credit_card");
        // 11 and 12 digits are below the {13,16} minimum
        assert!(!p.regex.is_match("12345678901"));
        assert!(!p.regex.is_match("123456789012"));
    }

    // --- Luhn ---

    #[test]
    fn luhn_valid_cards() {
        // Well-known test card numbers
        for card in &[
            "4111111111111111", // Visa
            "5500005555555559", // Mastercard
            "371449635398431",  // Amex (15 digits)
            "6011111111111117", // Discover
            "4532015112830366", // Visa
        ] {
            assert!(Luhn::check(card), "expected Luhn valid: {}", card);
        }
    }

    #[test]
    fn luhn_invalid_cards() {
        for card in &[
            "4111111111111112", // Visa off-by-one
            "1234567890123456", // random digits
            "9999999999999999", // all nines
            "4532015112830367", // Visa off-by-one
        ] {
            assert!(!Luhn::check(card), "expected Luhn invalid: {}", card);
        }
    }

    #[test]
    fn luhn_rejects_too_short() {
        assert!(!Luhn::check("123456789012")); // 12 digits
        assert!(!Luhn::check("1234"));
        assert!(!Luhn::check(""));
    }

    #[test]
    fn luhn_rejects_too_long() {
        // 20 digits — over the 19-digit max
        assert!(!Luhn::check("12345678901234567890"));
    }

    #[test]
    fn luhn_strips_spaces_and_dashes() {
        // Spaces and dashes are filtered; underlying digits are validated.
        assert!(Luhn::check("4111 1111 1111 1111"));
        assert!(Luhn::check("4111-1111-1111-1111"));
    }

    #[test]
    fn luhn_non_digit_chars_ignored() {
        // Only digits count; letters are stripped.
        // "4111111111111111" valid, so same with non-digit noise that doesn't change digit count.
        // Padding with letters shouldn't cause a 20-digit rejection since letters are filtered.
        assert!(Luhn::check("4111111111111111abc")); // still 16 digits after filtering
    }

    // --- classify_column ---

    #[test]
    fn classify_exact_single_token_names() {
        assert_eq!(classify_column("email"), Some("email"));
        assert_eq!(classify_column("phone"), Some("phone"));
        assert_eq!(classify_column("ssn"), Some("ssn"));
        assert_eq!(classify_column("dob"), Some("dob"));
        assert_eq!(classify_column("cvv"), Some("cvv"));
        assert_eq!(classify_column("npi"), Some("npi"));
        assert_eq!(classify_column("passport"), Some("passport"));
    }

    #[test]
    fn classify_synonyms() {
        assert_eq!(classify_column("mail"), Some("email"));
        assert_eq!(classify_column("mobile"), Some("phone"));
        assert_eq!(classify_column("tel"), Some("phone"));
        assert_eq!(classify_column("birth"), Some("dob"));
        assert_eq!(classify_column("birthday"), Some("dob"));
        assert_eq!(classify_column("birthdate"), Some("dob"));
        assert_eq!(classify_column("card"), Some("credit_card"));
        assert_eq!(classify_column("cvc"), Some("cvv"));
        assert_eq!(classify_column("license"), Some("license"));
        assert_eq!(classify_column("ip"), Some("ip"));
    }

    #[test]
    fn classify_underscore_separated() {
        assert_eq!(classify_column("email_address"), Some("email"));
        assert_eq!(classify_column("phone_number"), Some("phone"));
        assert_eq!(classify_column("first_name"), Some("name"));
        assert_eq!(classify_column("last_name"), Some("name"));
        assert_eq!(classify_column("full_name"), Some("name"));
        assert_eq!(classify_column("credit_card"), Some("credit_card"));
        assert_eq!(classify_column("card_number"), Some("credit_card"));
        assert_eq!(classify_column("license_number"), Some("license"));
        assert_eq!(classify_column("ip_address"), Some("ip"));
    }

    #[test]
    fn classify_camel_case() {
        assert_eq!(classify_column("userEmail"), Some("email"));
        assert_eq!(classify_column("mobileNumber"), Some("phone"));
        assert_eq!(classify_column("dateOfBirth"), Some("dob"));
        assert_eq!(classify_column("SSNField"), Some("ssn"));
        assert_eq!(classify_column("firstName"), Some("name"));
        assert_eq!(classify_column("lastName"), Some("name"));
        assert_eq!(classify_column("fullName"), Some("name"));
        assert_eq!(classify_column("cardNumber"), Some("credit_card"));
        assert_eq!(classify_column("ipAddress"), Some("ip"));
    }

    #[test]
    fn classify_all_caps() {
        assert_eq!(classify_column("EMAIL"), Some("email"));
        assert_eq!(classify_column("SSN"), Some("ssn"));
        assert_eq!(classify_column("PHONE"), Some("phone"));
    }

    #[test]
    fn classify_name_synonyms() {
        assert_eq!(classify_column("surname"), Some("name"));
        assert_eq!(classify_column("contact_surname"), Some("name"));
        assert_eq!(classify_column("first_names"), Some("name"));
        assert_eq!(classify_column("last_names"), Some("name"));
        assert_eq!(classify_column("contact_first_names"), Some("name"));
        assert_eq!(classify_column("given_name"), Some("name"));
        assert_eq!(classify_column("given_names"), Some("name"));
        assert_eq!(classify_column("family_name"), Some("name"));
        assert_eq!(classify_column("family_names"), Some("name"));
    }

    #[test]
    fn classify_name_prefix_allowlist() {
        assert_eq!(classify_column("contact_name"), Some("name"));
        assert_eq!(classify_column("customer_name"), Some("name"));
        assert_eq!(classify_column("person_name"), Some("name"));
        assert_eq!(classify_column("employee_name"), Some("name"));
        assert_eq!(classify_column("patient_name"), Some("name"));
        assert_eq!(classify_column("recipient_name"), Some("name"));
    }

    #[test]
    fn classify_name_bigram_no_false_positives() {
        // "name" alone must not trigger — only known prefixes/bigrams
        assert_eq!(classify_column("product_name"), None);
        assert_eq!(classify_column("company_name"), None);
        assert_eq!(classify_column("category_name"), None);
        assert_eq!(classify_column("account_name"), None);
        assert_eq!(classify_column("vendor_name"), None);
        assert_eq!(classify_column("name"), None);
    }

    #[test]
    fn classify_salutation_variants() {
        assert_eq!(classify_column("salutation"), Some("salutation"));
        assert_eq!(classify_column("personal_salutation"), Some("salutation"));
        assert_eq!(classify_column("individual_salutation"), Some("salutation"));
        assert_eq!(classify_column("salutation_value"), Some("salutation"));
        assert_eq!(classify_column("SALUTATION"), Some("salutation"));
        assert_eq!(classify_column("salutationCode"), Some("salutation"));
    }

    #[test]
    fn classify_returns_none_for_non_pii() {
        assert_eq!(classify_column("id"), None);
        assert_eq!(classify_column("count"), None);
        assert_eq!(classify_column("created_at"), None);
        assert_eq!(classify_column("status"), None);
        assert_eq!(classify_column("amount"), None);
        assert_eq!(classify_column("description"), None);
    }
}
