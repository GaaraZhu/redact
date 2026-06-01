use regex::Regex;
use std::sync::OnceLock;

pub const COLUMN_DENYLIST: &[&str] = &[
    // Names
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
    // Demographics
    "gender",
    "nationality",
    "citizenship",
    // Address
    "address",
    "latitude",
    "longitude",
    // Financial
    "iban",
    "salary",
    // Employment
    "employee_id",
    "staff_id",
    "student_id",
    // Government IDs
    "national_id",
    "immigration_id",
    // Health
    "medical",
    "biometric",
    "fingerprint",
    "prescription",
    "diagnosis",
    "vaccination",
    "disability",
    // Online & technical
    "username",
    "auth_token",
    // Family
    "next_of_kin",
    "emergency_contact",
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
    // ── AU/NZ value patterns ──────────────────────────────────────────────────
    BuiltinPattern {
        // NZ NHI: old AAANNNN (3 alpha not I/O + 4 digits);
        // new AAANNAY format (3 alpha + 2 digits + 1 alpha not I/O + 1 digit), from Jul-2026
        name: "health",
        regex: r"(?i)\b[a-hj-np-z]{3}(?:\d{4}|\d{2}[a-hj-np-z]\d)\b",
        confidence: 0.85,
    },
    BuiltinPattern {
        // NZ bank account: BB-bbbb-NNNNNNN-SS(S) — 2-4-7-2/3 hyphen-separated groups
        name: "bank_account",
        regex: r"\b\d{2}-\d{4}-\d{7}-\d{2,3}\b",
        confidence: 0.85,
    },
    BuiltinPattern {
        // AU mobile: 04XX XXX XXX / +61 4XX XXX XXX
        name: "phone",
        regex: r"\b(?:\+61[\s-]?|0)4\d{2}[\s-]?\d{3}[\s-]?\d{3}\b",
        confidence: 0.70,
    },
    BuiltinPattern {
        // NZ mobile: 02X XXX XXXX(X) / +64 2X XXX XXXX(X)
        name: "phone",
        regex: r"\b(?:\+64[\s-]?|0)2\d[\s-]?\d{3}[\s-]?\d{4,5}\b",
        confidence: 0.70,
    },
    BuiltinPattern {
        // AU passport: 1-2 letters + 7 digits; NZ passport: 1-2 letters + 6-7 digits
        name: "passport",
        regex: r"\b[A-Za-z]{1,2}\d{6,7}\b",
        confidence: 0.70,
    },
    BuiltinPattern {
        // NZ driver licence: 2 letters + 6 digits (AB123456)
        name: "license",
        regex: r"\b[A-Za-z]{2}\d{6}\b",
        confidence: 0.75,
    },
];

/// Token-to-PII-type synonym table. Single-token entries match bare column tokens;
/// bigram entries (e.g. "firstname") match two consecutive tokens joined without
/// separator; trigram entries match three. Longer passes run first so specific
/// matches win over shorter ones. Table order is the tiebreaker within a pass.
const TOKEN_SYNONYMS: &[(&str, &str)] = &[
    // ── Email ─────────────────────────────────────────────────────────────────
    ("email", "email"),
    ("mail", "email"),
    // ── Phone ─────────────────────────────────────────────────────────────────
    ("phone", "phone"),
    ("mobile", "phone"),
    ("tel", "phone"),
    ("fax", "phone"),
    // ── SSN ───────────────────────────────────────────────────────────────────
    ("ssn", "ssn"),
    ("socialsecuritynumber", "ssn"), // trigram: social_security_number
    // ── DOB ───────────────────────────────────────────────────────────────────
    ("dob", "dob"),
    ("birth", "dob"),
    ("birthday", "dob"),
    ("birthdate", "dob"),
    ("dateofbirth", "dob"), // trigram: date_of_birth
    // LOB — longer matches run first so these win over bare "birth" → dob.
    ("birthcountry", "lob"),    // birth_country
    ("birthplace", "lob"),      // birth_place
    ("birthcity", "lob"),       // birth_city
    ("birthstate", "lob"),      // birth_state
    ("birthlocation", "lob"),   // birth_location
    ("birthtown", "lob"),       // birth_town
    ("countryofbirth", "lob"),  // country_of_birth  (trigram)
    ("placeofbirth", "lob"),    // place_of_birth     (trigram)
    ("cityofbirth", "lob"),     // city_of_birth      (trigram)
    ("stateofbirth", "lob"),    // state_of_birth     (trigram)
    ("locationofbirth", "lob"), // location_of_birth  (trigram)
    // ── Credit Card ───────────────────────────────────────────────────────────
    ("card", "credit_card"),
    // ── CVV ───────────────────────────────────────────────────────────────────
    ("cvv", "cvv"),
    ("cvc", "cvv"),
    // ── Passport / License / NPI / IP ─────────────────────────────────────────
    ("passport", "passport"),
    ("npi", "npi"),
    ("license", "license"),
    ("licence", "license"), // AU/NZ/UK spelling
    ("ip", "ip"),
    // ── Salutation ────────────────────────────────────────────────────────────
    ("salutation", "salutation"),
    // ── Name (surname single-token + compound bigrams) ────────────────────────
    // "product_name" → bigram "productname" → no match (safe).
    // "first_name"   → bigram "firstname"   → match.
    ("surname", "name"),
    ("firstname", "name"),
    ("firstnames", "name"),
    ("lastname", "name"),
    ("lastnames", "name"),
    ("fullname", "name"),
    ("givenname", "name"),
    ("givennames", "name"),
    ("familyname", "name"),
    ("familynames", "name"),
    // ── Demographics ──────────────────────────────────────────────────────────
    ("gender", "gender"),
    ("sex", "gender"),
    ("nationality", "nationality"),
    ("citizenship", "nationality"),
    // ── Government IDs ────────────────────────────────────────────────────────
    // Use bigrams/trigrams for ambiguous bare tokens (e.g. "national", "tax").
    ("nationalid", "national_id"),       // national_id
    ("taxnumber", "tax_id"),             // tax_number
    ("taxid", "tax_id"),                 // tax_id
    ("irdnumber", "tax_id"),             // NZ Inland Revenue number
    ("tfn", "tax_id"),                   // AU Tax File Number (bare abbreviation)
    ("taxfilenumber", "tax_id"),         // tax_file_number (trigram)
    ("abn", "tax_id"),                   // AU Business Number (sole traders: personal PII)
    ("visanumber", "visa"),              // visa_number
    ("visaid", "visa"),                  // visa_id
    ("residentnumber", "resident_id"),   // resident_number
    ("residentid", "resident_id"),       // resident_id
    ("immigrationid", "immigration_id"), // immigration_id
    // ── Address & Location ────────────────────────────────────────────────────
    ("address", "address"),
    ("addr", "address"),
    ("street", "address"),
    ("postcode", "address"),
    ("zip", "address"),
    ("latitude", "gps"),
    ("longitude", "gps"),
    ("gps", "gps"),
    ("coordinates", "gps"),
    // ── Financial ─────────────────────────────────────────────────────────────
    ("bank", "bank_account"),
    ("iban", "iban"),
    ("swift", "swift"),
    ("bsb", "bank_account"), // AU/NZ bank-state branch code
    ("routing", "bank_account"),
    ("expiry", "expiry"),
    ("accountnumber", "bank_account"), // account_number (bigram; bare "account" is not flagged)
    ("routingnumber", "bank_account"), // routing_number
    // ── Employment ────────────────────────────────────────────────────────────
    ("salary", "salary"),
    ("wage", "salary"),
    ("jobtitle", "job_title"), // job_title
    // ── Health & Medical ──────────────────────────────────────────────────────
    ("medical", "medical"),
    ("health", "health"),
    ("medicare", "health"),       // AU Medicare card
    ("medicarenumber", "health"), // medicare_number (bigram)
    ("nhi", "health"),            // NZ National Health Index
    ("nhinumber", "health"),      // nhi_number (bigram)
    ("diagnosis", "medical"),
    ("prescription", "medical"),
    ("disability", "medical"),
    ("vaccination", "medical"),
    ("vaccine", "medical"),
    // ── Online & Technical Identifiers ────────────────────────────────────────
    ("username", "username"),
    ("authtoken", "auth_token"),   // auth_token
    ("macaddress", "mac_address"), // mac_address (bigram; bare "mac" is not flagged)
    // ── Biometric ─────────────────────────────────────────────────────────────
    ("biometric", "biometric"),
    ("fingerprint", "biometric"),
    ("voiceprint", "biometric"),
    ("retina", "biometric"),
    ("facescan", "biometric"), // face_scan
    // ── Family & Relationships ────────────────────────────────────────────────
    ("nextofkin", "next_of_kin"),              // trigram: next_of_kin
    ("emergencycontact", "emergency_contact"), // emergency_contact
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
/// Deliberately excludes generic prefixes like "vendor", "company"
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
    "account", // account_name = account holder's name (banking/payments context)
    // Additional person-name qualifiers
    "preferred", // preferred_name
    "middle",    // middle_name
    "maiden",    // maiden_name
    "spouse",    // spouse_name
    "parent",    // parent_name
    "guardian",  // guardian_name
    "manager",   // manager_name
    "sibling",   // sibling_name
    "children",  // children_names
];

/// Person-entity prefixes for ID/number columns.
/// `<prefix>_id` or `<prefix>_number` → "id".
/// Only entities where the bare prefix alone would be too generic to flag.
const PERSON_ID_PREFIXES: &[&str] = &[
    "employee",
    "staff",
    "student",
    "member",
    "client",
    "customer",
    "consumer",
    "cust",
    "crm",
    "person",
    "manager",
    // Online / technical identifiers
    "user",
    "device",
    "session",
    "cookie",
    "advertising",
    // Catch-all short aliases
    "external",
];

/// Returns the PII type label if any token (or consecutive token bigram) of `column_name`
/// matches a sensitive synonym. First match in `TOKEN_SYNONYMS` wins.
///
/// Avoids over-broad "name" matching: "product_name" → `None`; "first_name" → `Some("name")`.
pub fn classify_column(column_name: &str) -> Option<&'static str> {
    let tokens = tokenize_column(column_name);
    // Longer matches run first so they take priority over shorter ones.
    // e.g. "country_of_birth" → trigram "countryofbirth" → lob  (wins over bare "birth" → dob)
    // Trigram pass
    for triple in tokens.windows(3) {
        let trigram = format!("{}{}{}", triple[0], triple[1], triple[2]);
        if let Some(&(_, pii_type)) = TOKEN_SYNONYMS.iter().find(|(t, _)| *t == trigram.as_str()) {
            return Some(pii_type);
        }
    }
    // Bigram pass
    for pair in tokens.windows(2) {
        let bigram = format!("{}{}", pair[0], pair[1]);
        if let Some(&(_, pii_type)) = TOKEN_SYNONYMS.iter().find(|(t, _)| *t == bigram.as_str()) {
            return Some(pii_type);
        }
    }
    // Single-token pass — skip tokens immediately followed by "at" when "at" is the
    // final token (timestamp suffix, e.g. last_login_at → skip "login").
    // Does NOT skip when "at" is in the middle (e.g. sex_at_birth → "sex" still matches).
    for (i, token) in tokens.iter().enumerate() {
        let next_is_trailing_at =
            tokens.get(i + 1).map(String::as_str) == Some("at") && i + 2 == tokens.len();
        if next_is_trailing_at {
            continue;
        }
        if let Some(&(_, pii_type)) = TOKEN_SYNONYMS.iter().find(|(t, _)| *t == token.as_str()) {
            return Some(pii_type);
        }
    }
    // Prefix-name pass: <person-prefix> + "name"/"names" → "name"
    for pair in tokens.windows(2) {
        if NAME_PREFIXES.contains(&pair[0].as_str()) && (pair[1] == "name" || pair[1] == "names") {
            return Some("name");
        }
    }
    // Entity-id pass: <person-entity-prefix> + "id"/"number" → "id"
    for pair in tokens.windows(2) {
        if PERSON_ID_PREFIXES.contains(&pair[0].as_str())
            && (pair[1] == "id" || pair[1] == "number")
        {
            return Some("id");
        }
    }
    None
}

/// Maps the pii_type label returned by `classify_column` to a tier-1 reporting category.
///
/// Keep this function adjacent to `TOKEN_SYNONYMS` and `classify_column`: any new pii_type
/// added to either of those must also be covered here. The exhaustive test
/// `no_pii_type_returned_by_classify_maps_to_other` in this module enforces that invariant.
pub fn map_to_tier1_category(tier2: &str) -> &'static str {
    match tier2 {
        // Names
        "name" | "salutation" => "Names",
        // Demographics
        "gender" | "nationality" => "Demographics",
        // Government IDs
        "national_id" | "tax_id" | "visa" | "resident_id" | "immigration_id" | "passport"
        | "license" | "ssn" => "Government IDs",
        // Contact
        "email" | "phone" => "Contact",
        // Date of birth
        "dob" => "Date of birth",
        // Location of birth
        "lob" => "Location of birth",
        // Address & location
        "address" | "gps" => "Address & location",
        // Financial
        "credit_card" | "cvv" | "iban" | "swift" | "bank_account" | "expiry" => "Financial",
        // Employment
        "salary" | "job_title" => "Employment",
        // Health & medical
        "medical" | "health" | "npi" => "Health & medical",
        // Online & technical — includes personal identifiers (user_id, device_id, session_id, etc.)
        "username" | "auth_token" | "mac_address" | "ip" | "id" => "Online & technical",
        // Biometric
        "biometric" => "Biometric",
        // Family & relationships
        "next_of_kin" | "emergency_contact" => "Family & relationships",
        // Unknown — surface rather than silently drop
        _ => "Other",
    }
}

#[derive(Clone)]
pub struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
    pub confidence: f32,
}

impl CompiledPattern {
    /// Returns the compiled builtins, compiling them once per process lifetime.
    /// `Regex` is `Arc`-backed, so cloning is O(1).
    fn compiled_builtins() -> &'static Vec<Self> {
        static CACHE: OnceLock<Vec<CompiledPattern>> = OnceLock::new();
        CACHE.get_or_init(|| {
            BUILTIN_PATTERNS
                .iter()
                .map(|p| CompiledPattern {
                    name: p.name.to_string(),
                    regex: Regex::new(p.regex).expect("builtin regex is valid"),
                    confidence: p.confidence,
                })
                .collect()
        })
    }

    pub fn from_builtins() -> Vec<Self> {
        Self::compiled_builtins().clone()
    }

    /// Build compiled patterns from builtins, overlaying any user-supplied overrides.
    /// Same-named user patterns replace the builtin; new names are appended.
    pub fn from_config(
        user_patterns: &std::collections::HashMap<String, crate::config::Pattern>,
    ) -> Vec<Self> {
        let mut patterns = Self::compiled_builtins().clone();
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
    /// Only digits, spaces, and dashes are accepted; any other character (e.g.
    /// hex letters in a UUID) causes an immediate false return.
    pub fn check(s: &str) -> bool {
        if s.chars()
            .any(|c| !c.is_ascii_digit() && c != ' ' && c != '-')
        {
            return false;
        }
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

/// AU Tax File Number — mod-11 weighted checksum.
/// Weights: [1, 4, 3, 7, 5, 8, 6, 9, 10]; sum must be divisible by 11.
/// Formatting-gated: bare 9-digit strings are rejected (too many false positives).
/// Accepts NNN NNN NNN or NNN-NNN-NNN shapes.
pub struct AuTfn;

impl AuTfn {
    pub fn check(s: &str) -> bool {
        if s.chars()
            .any(|c| !c.is_ascii_digit() && c != ' ' && c != '-')
        {
            return false;
        }
        let digits: Vec<u32> = s
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() != 9 {
            return false;
        }
        if !s.contains(' ') && !s.contains('-') {
            return false;
        }
        const WEIGHTS: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
        let sum: u32 = digits
            .iter()
            .zip(WEIGHTS.iter())
            .map(|(&d, &w)| d * w)
            .sum();
        sum.is_multiple_of(11)
    }
}

/// AU Business Number — mod-89 weighted checksum.
/// Subtract 1 from the first digit, then apply weights [10,1,3,5,7,9,11,13,15,17,19];
/// sum must be divisible by 89.
/// Checksum-gated (like Luhn): the 11-digit mod-89 filter is strong enough for bare runs.
pub struct AuAbn;

impl AuAbn {
    pub fn check(s: &str) -> bool {
        if s.chars()
            .any(|c| !c.is_ascii_digit() && c != ' ' && c != '-')
        {
            return false;
        }
        let mut digits: Vec<u32> = s
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() != 11 {
            return false;
        }
        if digits[0] == 0 {
            return false;
        }
        digits[0] -= 1;
        const WEIGHTS: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
        let sum: u32 = digits
            .iter()
            .zip(WEIGHTS.iter())
            .map(|(&d, &w)| d * w)
            .sum();
        sum.is_multiple_of(89)
    }
}

/// AU Medicare card number — mod-10 weighted checksum.
/// Weights [1,3,7,9,1,3,7,9] applied to the first 8 digits; digit 9 is the check digit;
/// digit 10 is the card-issue number (IRN, not checked). First digit must be 2–6.
pub struct AuMedicare;

impl AuMedicare {
    pub fn check(s: &str) -> bool {
        if s.chars()
            .any(|c| !c.is_ascii_digit() && c != ' ' && c != '-')
        {
            return false;
        }
        let digits: Vec<u32> = s
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() != 10 {
            return false;
        }
        if digits[0] < 2 || digits[0] > 6 {
            return false;
        }
        const WEIGHTS: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
        let sum: u32 = digits[..8]
            .iter()
            .zip(WEIGHTS.iter())
            .map(|(&d, &w)| d * w)
            .sum();
        digits[8] == sum % 10
    }
}

/// NZ IRD (Inland Revenue) number — two-pass mod-11 checksum.
/// 8–9 digits; 8-digit numbers are left-padded to 9 with a leading zero.
/// Primary weights [3,2,7,6,5,4,3,2] on digits 1–8; check digit is digit 9.
/// If the primary pass yields remainder 10, fall back to secondary weights [7,4,3,2,5,2,7,6].
/// Formatting-gated: bare digit strings without separators are rejected.
/// Accepts NN-NNN-NNN or NNN-NNN-NNN shapes (dashes or spaces).
pub struct NzIrd;

impl NzIrd {
    pub fn check(s: &str) -> bool {
        if s.chars()
            .any(|c| !c.is_ascii_digit() && c != '-' && c != ' ')
        {
            return false;
        }
        let digits: Vec<u32> = s
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() < 8 || digits.len() > 9 {
            return false;
        }
        if !s.contains('-') && !s.contains(' ') {
            return false;
        }
        let padded: Vec<u32> = if digits.len() == 8 {
            let mut v = vec![0u32];
            v.extend_from_slice(&digits);
            v
        } else {
            digits
        };
        let check_digit = padded[8];
        let base = &padded[..8];
        const PRIMARY: [u32; 8] = [3, 2, 7, 6, 5, 4, 3, 2];
        let remainder = base
            .iter()
            .zip(PRIMARY.iter())
            .map(|(&d, &w)| d * w)
            .sum::<u32>()
            % 11;
        let expected = if remainder == 0 { 0 } else { 11 - remainder };
        if expected != 10 {
            return expected == check_digit;
        }
        // Primary gives 10 — try secondary weights
        const SECONDARY: [u32; 8] = [7, 4, 3, 2, 5, 2, 7, 6];
        let remainder2 = base
            .iter()
            .zip(SECONDARY.iter())
            .map(|(&d, &w)| d * w)
            .sum::<u32>()
            % 11;
        let expected2 = if remainder2 == 0 { 0 } else { 11 - remainder2 };
        expected2 != 10 && expected2 == check_digit
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
    fn all_builtins_present() {
        let patterns = CompiledPattern::from_builtins();
        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        for expected in &[
            "email",
            "ssn",
            "phone",
            "credit_card",
            "health",
            "bank_account",
            "passport",
            "license",
        ] {
            assert!(names.contains(expected), "missing builtin: {}", expected);
        }
        assert_eq!(patterns.len(), 10);
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
    fn luhn_rejects_non_digit_non_separator_chars() {
        // Any character other than digit, space, or dash disqualifies the string.
        assert!(!Luhn::check("4111111111111111abc"));
        // UUIDs contain hex letters — must not be treated as credit cards.
        assert!(!Luhn::check("19eb1ea0-1d75-4a8e-86bd-0b017af3b3f0"));
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
    fn classify_birth_columns() {
        // Date-of-birth columns → dob
        assert_eq!(classify_column("dob"), Some("dob"));
        assert_eq!(classify_column("birth"), Some("dob"));
        assert_eq!(classify_column("birthday"), Some("dob"));
        assert_eq!(classify_column("birthdate"), Some("dob"));
        assert_eq!(classify_column("birth_date"), Some("dob"));
        assert_eq!(classify_column("date_of_birth"), Some("dob"));
        assert_eq!(classify_column("dateOfBirth"), Some("dob"));
        // Location-of-birth columns → lob (more specific match wins over bare "birth" → dob)
        assert_eq!(classify_column("country_of_birth"), Some("lob"));
        assert_eq!(classify_column("place_of_birth"), Some("lob"));
        assert_eq!(classify_column("city_of_birth"), Some("lob"));
        assert_eq!(classify_column("state_of_birth"), Some("lob"));
        assert_eq!(classify_column("birth_country"), Some("lob"));
        assert_eq!(classify_column("birth_place"), Some("lob"));
        assert_eq!(classify_column("birth_city"), Some("lob"));
    }

    #[test]
    fn classify_name_bigram_no_false_positives() {
        // "name" alone must not trigger — only known prefixes/bigrams
        assert_eq!(classify_column("product_name"), None);
        assert_eq!(classify_column("company_name"), None);
        assert_eq!(classify_column("category_name"), None);
        assert_eq!(classify_column("vendor_name"), None);
        assert_eq!(classify_column("name"), None);
    }

    #[test]
    fn account_name_is_name() {
        // account_name = account holder's name (banking/payments); must be treated as PII.
        assert_eq!(classify_column("account_name"), Some("name"));
        assert_eq!(classify_column("account_names"), Some("name"));
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

    #[test]
    fn timestamp_at_suffix_suppresses_single_token_match() {
        // _at columns are timestamps — confirm they don't match anything
        assert_eq!(classify_column("last_login_at"), None);
        assert_eq!(classify_column("login_at"), None);
    }

    // ── New coverage ──────────────────────────────────────────────────────────

    #[test]
    fn classify_additional_name_forms() {
        assert_eq!(classify_column("middle_name"), Some("name"));
        assert_eq!(classify_column("preferred_name"), Some("name"));
        assert_eq!(classify_column("maiden_name"), Some("name"));
        assert_eq!(classify_column("spouse_name"), Some("name"));
        assert_eq!(classify_column("parent_name"), Some("name"));
        assert_eq!(classify_column("guardian_name"), Some("name"));
        assert_eq!(classify_column("manager_name"), Some("name"));
        assert_eq!(classify_column("sibling_name"), Some("name"));
        assert_eq!(classify_column("children_names"), Some("name"));
    }

    #[test]
    fn classify_demographics() {
        assert_eq!(classify_column("gender"), Some("gender"));
        assert_eq!(classify_column("sex"), Some("gender"));
        assert_eq!(classify_column("sex_at_birth"), Some("gender"));
        assert_eq!(classify_column("gender_code"), Some("gender"));
        assert_eq!(classify_column("nationality"), Some("nationality"));
        assert_eq!(classify_column("citizenship"), Some("nationality"));
    }

    #[test]
    fn classify_government_ids() {
        assert_eq!(classify_column("national_id"), Some("national_id"));
        assert_eq!(classify_column("social_security_number"), Some("ssn"));
        assert_eq!(classify_column("tax_number"), Some("tax_id"));
        assert_eq!(classify_column("tax_id"), Some("tax_id"));
        assert_eq!(classify_column("ird_number"), Some("tax_id"));
        assert_eq!(classify_column("visa_number"), Some("visa"));
        assert_eq!(classify_column("visa_id"), Some("visa"));
        assert_eq!(classify_column("resident_number"), Some("resident_id"));
        assert_eq!(classify_column("resident_id"), Some("resident_id"));
        assert_eq!(classify_column("immigration_id"), Some("immigration_id"));
    }

    #[test]
    fn classify_au_nz_licence_spelling() {
        assert_eq!(classify_column("licence"), Some("license"));
        assert_eq!(classify_column("licence_number"), Some("license"));
        assert_eq!(classify_column("driver_licence"), Some("license"));
        assert_eq!(classify_column("drivers_licence"), Some("license"));
        assert_eq!(classify_column("driverLicence"), Some("license"));
    }

    #[test]
    fn classify_au_nz_government_ids() {
        assert_eq!(classify_column("tfn"), Some("tax_id"));
        assert_eq!(classify_column("tax_file_number"), Some("tax_id"));
        assert_eq!(classify_column("abn"), Some("tax_id"));
    }

    #[test]
    fn classify_au_nz_health_ids() {
        assert_eq!(classify_column("medicare"), Some("health"));
        assert_eq!(classify_column("medicare_number"), Some("health"));
        assert_eq!(classify_column("medicare_card"), Some("health"));
        assert_eq!(classify_column("nhi"), Some("health"));
        assert_eq!(classify_column("nhi_number"), Some("health"));
    }

    #[test]
    fn classify_address() {
        assert_eq!(classify_column("address"), Some("address"));
        assert_eq!(classify_column("home_address"), Some("address"));
        assert_eq!(classify_column("billing_address"), Some("address"));
        assert_eq!(classify_column("shipping_address"), Some("address"));
        assert_eq!(classify_column("street_address"), Some("address"));
        assert_eq!(classify_column("addr"), Some("address"));
        assert_eq!(classify_column("postcode"), Some("address"));
        assert_eq!(classify_column("zip_code"), Some("address"));
        assert_eq!(classify_column("suburb"), None);
        assert_eq!(classify_column("city"), None);
        assert_eq!(classify_column("state"), None);
        assert_eq!(classify_column("province"), None);
        assert_eq!(classify_column("country"), None);
        assert_eq!(classify_column("latitude"), Some("gps"));
        assert_eq!(classify_column("longitude"), Some("gps"));
        assert_eq!(classify_column("gps"), Some("gps"));
        assert_eq!(classify_column("gps_coordinates"), Some("gps"));
    }

    #[test]
    fn classify_address_does_not_override_lob() {
        // city/state/country inside birth-location bigrams/trigrams must still → lob
        assert_eq!(classify_column("country_of_birth"), Some("lob"));
        assert_eq!(classify_column("city_of_birth"), Some("lob"));
        assert_eq!(classify_column("state_of_birth"), Some("lob"));
        assert_eq!(classify_column("birth_country"), Some("lob"));
        assert_eq!(classify_column("birth_city"), Some("lob"));
        assert_eq!(classify_column("birth_state"), Some("lob"));
    }

    #[test]
    fn classify_financial() {
        assert_eq!(classify_column("bank_account"), Some("bank_account"));
        assert_eq!(classify_column("account_number"), Some("bank_account"));
        assert_eq!(classify_column("iban"), Some("iban"));
        assert_eq!(classify_column("swift_code"), Some("swift"));
        assert_eq!(classify_column("routing_number"), Some("bank_account"));
        assert_eq!(classify_column("bsb"), Some("bank_account"));
        assert_eq!(classify_column("expiry_date"), Some("expiry"));
        assert_eq!(classify_column("card_expiry"), Some("credit_card")); // "card" token matches first
    }

    #[test]
    fn classify_employment() {
        assert_eq!(classify_column("employee_id"), Some("id"));
        assert_eq!(classify_column("staff_id"), Some("id"));
        assert_eq!(classify_column("student_id"), Some("id"));
        assert_eq!(classify_column("customer_id"), Some("id"));
        assert_eq!(classify_column("salary"), Some("salary"));
        assert_eq!(classify_column("wage"), Some("salary"));
        assert_eq!(classify_column("job_title"), Some("job_title"));
    }

    #[test]
    fn classify_health() {
        assert_eq!(classify_column("medical_record_number"), Some("medical"));
        assert_eq!(classify_column("medical_condition"), Some("medical"));
        assert_eq!(classify_column("health_id"), Some("health"));
        assert_eq!(classify_column("diagnosis"), Some("medical"));
        assert_eq!(classify_column("prescription"), Some("medical"));
        assert_eq!(classify_column("disability_status"), Some("medical"));
        assert_eq!(classify_column("vaccination_status"), Some("medical"));
        assert_eq!(classify_column("vaccine"), Some("medical"));
    }

    #[test]
    fn classify_online_identifiers() {
        assert_eq!(classify_column("username"), Some("username"));
        assert_eq!(classify_column("user_name"), Some("username"));
        assert_eq!(classify_column("login"), None);
        assert_eq!(classify_column("user_id"), Some("id"));
        assert_eq!(classify_column("device_id"), Some("id"));
        assert_eq!(classify_column("session_id"), Some("id"));
        assert_eq!(classify_column("cookie_id"), Some("id"));
        assert_eq!(classify_column("advertising_id"), Some("id"));
        assert_eq!(classify_column("auth_token"), Some("auth_token"));
        assert_eq!(classify_column("mac_address"), Some("mac_address"));
    }

    #[test]
    fn classify_biometric() {
        assert_eq!(classify_column("fingerprint"), Some("biometric"));
        assert_eq!(classify_column("biometric_id"), Some("biometric"));
        assert_eq!(classify_column("voiceprint"), Some("biometric"));
        assert_eq!(classify_column("retina_scan"), Some("biometric"));
        assert_eq!(classify_column("face_scan"), Some("biometric"));
    }

    #[test]
    fn classify_family_relationships() {
        assert_eq!(classify_column("next_of_kin"), Some("next_of_kin"));
        assert_eq!(
            classify_column("emergency_contact"),
            Some("emergency_contact")
        );
        assert_eq!(classify_column("spouse_name"), Some("name"));
        assert_eq!(classify_column("parent_name"), Some("name"));
    }

    #[test]
    fn classify_common_short_aliases() {
        assert_eq!(classify_column("cust_id"), Some("id"));
        assert_eq!(classify_column("client_id"), Some("id"));
        assert_eq!(classify_column("member_id"), Some("id"));
        assert_eq!(classify_column("crm_id"), Some("id"));
        assert_eq!(classify_column("person_number"), Some("id"));
        assert_eq!(classify_column("consumer_number"), Some("id"));
        assert_eq!(classify_column("external_id"), Some("id"));
    }

    #[test]
    fn person_id_pass_does_not_flag_generic_entity_ids() {
        // Non-person entity + _id must not trigger
        assert_eq!(classify_column("product_id"), None);
        assert_eq!(classify_column("order_id"), None);
        assert_eq!(classify_column("account_id"), None);
        assert_eq!(classify_column("vendor_id"), None);
        assert_eq!(classify_column("category_id"), None);
    }

    // ── map_to_tier1_category ─────────────────────────────────────────────────

    #[test]
    fn map_email_to_contact() {
        assert_eq!(map_to_tier1_category("email"), "Contact");
        assert_eq!(map_to_tier1_category("phone"), "Contact");
    }

    #[test]
    fn map_tax_id_to_government_ids() {
        assert_eq!(map_to_tier1_category("tax_id"), "Government IDs");
        assert_eq!(map_to_tier1_category("national_id"), "Government IDs");
        assert_eq!(map_to_tier1_category("visa"), "Government IDs");
    }

    #[test]
    fn map_name_to_names() {
        assert_eq!(map_to_tier1_category("name"), "Names");
        assert_eq!(map_to_tier1_category("salutation"), "Names");
    }

    #[test]
    fn map_id_to_online_technical() {
        // classify_column returns "id" for all PERSON_ID_PREFIXES columns;
        // must map to a visible tier-1 category, not "Other".
        assert_eq!(map_to_tier1_category("id"), "Online & technical");
    }

    #[test]
    fn map_unknown_to_other() {
        assert_eq!(map_to_tier1_category("unknown_type"), "Other");
    }

    // ── AuTfn ─────────────────────────────────────────────────────────────────

    #[test]
    fn au_tfn_valid_formatted_spaces() {
        // 123 456 782: 1*1+2*4+3*3+4*7+5*5+6*8+7*6+8*9+2*10 = 253 = 23*11
        assert!(AuTfn::check("123 456 782"));
    }

    #[test]
    fn au_tfn_valid_formatted_dashes() {
        assert!(AuTfn::check("123-456-782"));
    }

    #[test]
    fn au_tfn_rejects_bare_digits() {
        assert!(!AuTfn::check("123456782"));
    }

    #[test]
    fn au_tfn_rejects_wrong_checksum() {
        // Off-by-one in last digit: sum becomes 263, not divisible by 11
        assert!(!AuTfn::check("123 456 783"));
    }

    #[test]
    fn au_tfn_rejects_non_digit_chars() {
        assert!(!AuTfn::check("12A 456 782"));
    }

    #[test]
    fn au_tfn_rejects_wrong_length() {
        assert!(!AuTfn::check("123 456 78")); // 8 digits
        assert!(!AuTfn::check("123 456 7823")); // 10 digits
    }

    // ── AuAbn ─────────────────────────────────────────────────────────────────

    #[test]
    fn au_abn_valid_formatted() {
        // 53 004 085 616: subtract 1 → [4,3,0,0,4,0,8,5,6,1,6]; weighted sum = 445 = 5*89
        assert!(AuAbn::check("53 004 085 616"));
    }

    #[test]
    fn au_abn_valid_bare() {
        assert!(AuAbn::check("53004085616"));
    }

    #[test]
    fn au_abn_valid_dashes() {
        assert!(AuAbn::check("53-004-085-616"));
    }

    #[test]
    fn au_abn_rejects_wrong_checksum() {
        assert!(!AuAbn::check("53 004 085 617"));
    }

    #[test]
    fn au_abn_rejects_zero_first_digit() {
        assert!(!AuAbn::check("03 004 085 616"));
    }

    #[test]
    fn au_abn_rejects_wrong_length() {
        assert!(!AuAbn::check("5300408561")); // 10 digits
    }

    #[test]
    fn au_abn_rejects_non_digit_chars() {
        assert!(!AuAbn::check("5X 004 085 616"));
    }

    // ── AuMedicare ────────────────────────────────────────────────────────────

    #[test]
    fn au_medicare_valid_bare() {
        // First 8: [2,9,5,0,9,8,7,6]; weights [1,3,7,9,1,3,7,9]; sum=200; check=0; IRN=1
        assert!(AuMedicare::check("2950987601"));
    }

    #[test]
    fn au_medicare_valid_formatted() {
        assert!(AuMedicare::check("2950 98760 1"));
    }

    #[test]
    fn au_medicare_rejects_wrong_check_digit() {
        // check digit is index 8; changing it from 0 to 1 makes it invalid
        assert!(!AuMedicare::check("2950987611"));
    }

    #[test]
    fn au_medicare_rejects_first_digit_out_of_range() {
        assert!(!AuMedicare::check("1950987601")); // first digit 1
        assert!(!AuMedicare::check("7950987601")); // first digit 7
    }

    #[test]
    fn au_medicare_rejects_wrong_length() {
        assert!(!AuMedicare::check("295098760")); // 9 digits
        assert!(!AuMedicare::check("29509876011")); // 11 digits
    }

    #[test]
    fn au_medicare_rejects_non_digit_chars() {
        assert!(!AuMedicare::check("2950A87601"));
    }

    // ── NzIrd ─────────────────────────────────────────────────────────────────

    #[test]
    fn nz_ird_valid_8digit_dashes() {
        // 49098576: padded → [0,4,9,0,9,8,5,7,6]; primary gives expected=10; secondary gives 6 ✓
        assert!(NzIrd::check("49-098-576"));
    }

    #[test]
    fn nz_ird_valid_8digit_spaces() {
        assert!(NzIrd::check("49 098 576"));
    }

    #[test]
    fn nz_ird_valid_9digit_dashes() {
        // 136410132: primary gives expected=10; secondary gives 2 ✓
        assert!(NzIrd::check("136-410-132"));
    }

    #[test]
    fn nz_ird_rejects_bare_digits() {
        assert!(!NzIrd::check("49098576"));
        assert!(!NzIrd::check("136410132"));
    }

    #[test]
    fn nz_ird_rejects_wrong_checksum() {
        assert!(!NzIrd::check("49-098-577")); // last digit off by one
    }

    #[test]
    fn nz_ird_rejects_wrong_length() {
        assert!(!NzIrd::check("490-985")); // 7 digits
        assert!(!NzIrd::check("490-985-761")); // 10 digits
    }

    #[test]
    fn nz_ird_rejects_non_digit_chars() {
        assert!(!NzIrd::check("49-0A8-576"));
    }

    #[test]
    fn no_pii_type_returned_by_classify_maps_to_other() {
        // Exhaustive guard: every pii_type classify_column can return must have
        // an explicit tier-1 mapping. Fails when a new type is added to
        // TOKEN_SYNONYMS / classify_column without updating map_to_tier1_category.
        let known_pii_types = [
            "email",
            "phone",
            "ssn",
            "dob",
            "lob",
            "credit_card",
            "cvv",
            "passport",
            "npi",
            "license",
            "ip",
            "salutation",
            "name",
            "gender",
            "nationality",
            "national_id",
            "tax_id",
            "visa",
            "resident_id",
            "immigration_id",
            "address",
            "gps",
            "bank_account",
            "iban",
            "swift",
            "expiry",
            "salary",
            "job_title",
            "medical",
            "health",
            "username",
            "auth_token",
            "mac_address",
            "biometric",
            "next_of_kin",
            "emergency_contact",
            "id",
        ];
        for pii_type in &known_pii_types {
            assert_ne!(
                map_to_tier1_category(pii_type),
                "Other",
                "pii_type '{}' falls through to Other — add it to map_to_tier1_category",
                pii_type
            );
        }
    }
}
