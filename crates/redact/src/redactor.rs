use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;

struct Pattern {
    name: &'static str,
    regex: Regex,
    confidence: f32,
}

fn patterns() -> &'static [Pattern] {
    static COMPILED: OnceLock<Vec<Pattern>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        vec![
            Pattern {
                name: "email",
                regex: Regex::new(r"(?i)[\w.+\-]+@[\w\-]+\.[a-z]{2,}").unwrap(),
                confidence: 0.95,
            },
            Pattern {
                name: "ssn",
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                confidence: 0.90,
            },
            Pattern {
                name: "phone",
                regex: Regex::new(r"\b(\+1[\s.]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b").unwrap(),
                confidence: 0.70,
            },
        ]
    })
}

const PII_COLUMN_NAMES: &[&str] = &[
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
    "birthdate",
];

const COLUMN_NAME_BOOST: f32 = 0.15;
const CONFIDENCE_THRESHOLD: f32 = 0.8;

pub struct RedactResult {
    pub value: Value,
    pub redacted_count: usize,
    pub types: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn redact(payload: Value) -> RedactResult {
    let mut count = 0usize;
    let mut type_set: HashSet<String> = HashSet::new();
    let mut warnings = Vec::new();

    let value = walk(payload, None, &mut count, &mut type_set, &mut warnings);

    let mut types: Vec<String> = type_set.into_iter().collect();
    types.sort();

    RedactResult {
        value,
        redacted_count: count,
        types,
        warnings,
    }
}

fn walk(
    val: Value,
    key: Option<String>,
    count: &mut usize,
    types: &mut HashSet<String>,
    warnings: &mut Vec<String>,
) -> Value {
    match val {
        Value::String(s) => scan_string(s, key.as_deref(), count, types, warnings),
        Value::Object(map) => {
            let new_map = map
                .into_iter()
                .map(|(k, v)| {
                    let new_v = walk(v, Some(k.clone()), count, types, warnings);
                    (k, new_v)
                })
                .collect();
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|v| walk(v, key.clone(), count, types, warnings))
                .collect(),
        ),
        other => other,
    }
}

fn scan_string(
    s: String,
    key: Option<&str>,
    count: &mut usize,
    types: &mut HashSet<String>,
    warnings: &mut Vec<String>,
) -> Value {
    let is_pii_column = key
        .map(|k| PII_COLUMN_NAMES.contains(&k.to_lowercase().as_str()))
        .unwrap_or(false);

    // Luhn check: only consider strings that look like card numbers
    let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
    let looks_like_card = s
        .chars()
        .all(|c| c.is_ascii_digit() || c == ' ' || c == '-');
    if looks_like_card && (13..=19).contains(&digit_count) {
        let digits: Vec<u32> = s
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if luhn(&digits) {
            *count += 1;
            types.insert("credit_card".to_string());
            return Value::String("[PII:credit_card]".to_string());
        }
    }

    // Regex pattern matching
    let mut best: Option<(&str, f32)> = None;
    for p in patterns() {
        if p.regex.is_match(&s) {
            let score = if is_pii_column {
                (p.confidence + COLUMN_NAME_BOOST).min(1.0)
            } else {
                p.confidence
            };
            if best.map(|(_, b)| score > b).unwrap_or(true) {
                best = Some((p.name, score));
            }
        }
    }

    if let Some((name, score)) = best {
        if score >= CONFIDENCE_THRESHOLD {
            *count += 1;
            types.insert(name.to_string());
            return Value::String(format!("[PII:{}]", name));
        }
        warnings.push(format!(
            "low-confidence: key={} pattern={} score={:.2}",
            key.unwrap_or("?"),
            name,
            score
        ));
    }

    Value::String(s)
}

fn luhn(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_email_in_object() {
        let input = json!({"id": 1, "email": "alice@example.com"});
        let r = redact(input);
        assert_eq!(r.value["email"], "[PII:email]");
        assert_eq!(r.value["id"], 1);
        assert_eq!(r.redacted_count, 1);
        assert!(r.types.contains(&"email".to_string()));
    }

    #[test]
    fn redacts_ssn() {
        let input = json!({"ssn": "123-45-6789"});
        let r = redact(input);
        assert_eq!(r.value["ssn"], "[PII:ssn]");
    }

    #[test]
    fn phone_needs_column_boost_to_pass_threshold() {
        // phone base confidence = 0.70, column_name_boost = 0.15 → 0.85 ≥ 0.80
        let input = json!({"phone": "555-123-4567"});
        let r = redact(input);
        assert_eq!(r.value["phone"], "[PII:phone]");
    }

    #[test]
    fn phone_without_pii_column_stays_below_threshold() {
        // phone base confidence = 0.70 < 0.80, not a PII column name
        let input = json!({"contact_info": "555-123-4567"});
        let r = redact(input);
        assert_eq!(r.value["contact_info"], "555-123-4567");
        assert_eq!(r.redacted_count, 0);
        assert!(!r.warnings.is_empty()); // warned but not redacted
    }

    #[test]
    fn redacts_credit_card_via_luhn() {
        // Standard Visa test number
        let input = json!({"card": "4111111111111111"});
        let r = redact(input);
        assert_eq!(r.value["card"], "[PII:credit_card]");
    }

    #[test]
    fn luhn_false_negative_not_redacted() {
        // 16 digits but fails Luhn
        let input = json!({"card": "1234567890123456"});
        let r = redact(input);
        assert_eq!(r.value["card"], "1234567890123456");
    }

    #[test]
    fn non_pii_passthrough() {
        let input = json!({"id": 42, "name": "Widget", "count": 100});
        let r = redact(input);
        assert_eq!(r.redacted_count, 0);
        assert_eq!(r.value["name"], "Widget");
    }

    #[test]
    fn nested_rows_array() {
        let input = json!({
            "rows": [
                {"id": 1, "email": "alice@example.com", "ssn": "111-22-3333"},
                {"id": 2, "email": "bob@example.com",   "ssn": "444-55-6666"}
            ],
            "count": 2
        });
        let r = redact(input);
        let rows = r.value["rows"].as_array().unwrap();
        assert_eq!(rows[0]["email"], "[PII:email]");
        assert_eq!(rows[0]["ssn"], "[PII:ssn]");
        assert_eq!(rows[1]["email"], "[PII:email]");
        assert_eq!(r.redacted_count, 4);
    }

    #[test]
    fn null_value_passthrough() {
        let input = json!({"email": null});
        let r = redact(input);
        assert_eq!(r.value["email"], Value::Null);
        assert_eq!(r.redacted_count, 0);
    }

    #[test]
    fn luhn_valid_vectors() {
        // Known-good Luhn numbers
        for card in &["4111111111111111", "5500005555555559", "371449635398431"] {
            let digits: Vec<u32> = card.chars().filter_map(|c| c.to_digit(10)).collect();
            assert!(luhn(&digits), "expected Luhn pass for {}", card);
        }
    }

    #[test]
    fn luhn_invalid_vectors() {
        for card in &["4111111111111112", "1234567890123456"] {
            let digits: Vec<u32> = card.chars().filter_map(|c| c.to_digit(10)).collect();
            assert!(!luhn(&digits), "expected Luhn fail for {}", card);
        }
    }
}
