use std::collections::{BTreeSet, HashMap};

use serde_json::{Map, Value};

use crate::config::PiiConfig;
use crate::patterns::{classify_column, CompiledPattern, Luhn};

// ── Public types ──────────────────────────────────────────────────────────────

/// Gate 1 → Gate 2 handoff. Gate 1 populates this; Gate 2 consumes it.
pub struct RedactPlan {
    /// Columns Gate 1 marked for guaranteed redaction.
    /// Key = JSON key name (lowercased, alias-resolved). Value = PII type label.
    pub forced_columns: HashMap<String, String>,
    /// Warnings to merge into _gate_summary regardless of Gate 2's findings.
    pub warnings: Vec<String>,
    /// True when Gate 1 already exited with an error (action = reject).
    /// In that case `redact()` should never be called.
    pub rejected: bool,
}

impl RedactPlan {
    pub fn empty() -> Self {
        Self {
            forced_columns: HashMap::new(),
            warnings: Vec::new(),
            rejected: false,
        }
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Shape {
    Error,
    Object,
    Array,
    Other,
}

struct RedactSummary {
    redacted: usize,
    types: BTreeSet<String>,
    warnings: Vec<String>,
}

impl RedactSummary {
    fn new() -> Self {
        Self {
            redacted: 0,
            types: BTreeSet::new(),
            warnings: Vec::new(),
        }
    }

    fn to_value(&self) -> Value {
        let types: Vec<&str> = self.types.iter().map(String::as_str).collect();
        serde_json::json!({
            "redacted": self.redacted,
            "types": types,
            "warnings": self.warnings,
        })
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Redact `payload` using `plan` (from Gate 1) and `config`.
/// Returns the redacted JSON with `_gate_summary` attached according to payload shape.
/// Error-shaped payloads (`{"error": ...}`) are returned unchanged.
pub fn redact(payload: Value, plan: &RedactPlan, config: &PiiConfig) -> Value {
    let shape = detect_shape(&payload);
    if shape == Shape::Error {
        return payload;
    }

    let patterns = CompiledPattern::from_config(&config.patterns);
    let effective_names = config.effective_column_names();
    let mut summary = RedactSummary::new();

    let redacted_payload = walk(
        payload,
        None,
        plan,
        config,
        &patterns,
        &effective_names,
        &mut summary,
    );

    for w in &plan.warnings {
        summary.warnings.push(w.clone());
    }

    apply_summary(redacted_payload, &summary, config.include_summary, &shape)
}

// ── Shape detection ───────────────────────────────────────────────────────────

fn detect_shape(val: &Value) -> Shape {
    match val {
        Value::Object(map) if map.contains_key("error") => Shape::Error,
        Value::Object(_) => Shape::Object,
        Value::Array(_) => Shape::Array,
        _ => Shape::Other,
    }
}

// ── Summary attachment ────────────────────────────────────────────────────────

fn apply_summary(
    payload: Value,
    summary: &RedactSummary,
    include_summary: bool,
    shape: &Shape,
) -> Value {
    if !include_summary {
        return payload;
    }
    let sv = summary.to_value();
    match shape {
        Shape::Object => {
            if let Value::Object(mut map) = payload {
                map.insert("_gate_summary".to_string(), sv);
                Value::Object(map)
            } else {
                payload
            }
        }
        Shape::Array => {
            serde_json::json!({ "rows": payload, "_gate_summary": sv })
        }
        _ => payload,
    }
}

// ── Tree walk ─────────────────────────────────────────────────────────────────

fn walk(
    val: Value,
    key: Option<&str>,
    plan: &RedactPlan,
    config: &PiiConfig,
    patterns: &[CompiledPattern],
    effective_names: &[String],
    summary: &mut RedactSummary,
) -> Value {
    match val {
        Value::String(s) => scan_string(s, key, plan, config, patterns, effective_names, summary),
        Value::Object(map) => {
            let new_map: Map<String, Value> = map
                .into_iter()
                .map(|(k, v)| {
                    let new_v = walk(
                        v,
                        Some(k.as_str()),
                        plan,
                        config,
                        patterns,
                        effective_names,
                        summary,
                    );
                    (k, new_v)
                })
                .collect();
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|v| walk(v, key, plan, config, patterns, effective_names, summary))
                .collect(),
        ),
        other => other,
    }
}

// ── Per-value scanner ─────────────────────────────────────────────────────────

fn scan_string(
    s: String,
    key: Option<&str>,
    plan: &RedactPlan,
    config: &PiiConfig,
    patterns: &[CompiledPattern],
    effective_names: &[String],
    summary: &mut RedactSummary,
) -> Value {
    // Idempotency: skip already-redacted placeholders so a second pass doesn't
    // inflate the summary count.
    if is_redaction_placeholder(&s, &config.redaction) {
        return Value::String(s);
    }

    let template = &config.redaction;
    let key_lower = key.map(|k| k.to_lowercase());

    // 1. Gate 1 forced columns (keys are pre-lowercased by Gate 1).
    if let Some(ref k) = key_lower {
        if let Some(type_label) = plan.forced_columns.get(k.as_str()) {
            return do_redact(type_label, template, summary);
        }
    }

    // 2. Token-based column classification — catches camelCase, synonyms, etc.
    //    Force-redacts any value under a PII-named key, regardless of content.
    if let Some(k) = key {
        if let Some(pii_type) = classify_column(k) {
            return do_redact(pii_type, template, summary);
        }
    }

    // 3. Exact match against the effective column-name list.
    //    Covers user-supplied column names not handled by the synonym table.
    if let Some(ref k) = key_lower {
        if effective_names.iter().any(|n| n == k) {
            return do_redact(k.as_str(), template, summary);
        }
    }

    // 4. JSONB: if the value is a serialised JSON object or array, scan it recursively.
    if let Ok(inner) = serde_json::from_str::<Value>(&s) {
        if matches!(inner, Value::Object(_) | Value::Array(_)) {
            let count_before = summary.redacted;
            let walked = walk(inner, key, plan, config, patterns, effective_names, summary);
            if summary.redacted > count_before {
                return Value::String(serde_json::to_string(&walked).unwrap_or(s));
            }
            return Value::String(s);
        }
    }

    // 5. Luhn check — always redacts Luhn-valid card-shaped strings.
    if Luhn::check(&s) {
        return do_redact("credit_card", template, summary);
    }

    // 6. Regex pattern scan. column_name_boost is not applied here: any column
    //    whose name matched the denylist was already handled in steps 1–3.
    let mut best: Option<(&str, f32)> = None;
    for p in patterns {
        if p.regex.is_match(&s) {
            let score = p.confidence;
            if best.map(|(_, b)| score > b).unwrap_or(true) {
                best = Some((p.name.as_str(), score));
            }
        }
    }
    if let Some((name, score)) = best {
        if score >= config.confidence_threshold {
            return do_redact(name, template, summary);
        }
        // Low-confidence: warn but do not redact. Raw value is intentionally excluded.
        summary.warnings.push(format!(
            "low-confidence match: key={} pattern={} score={:.2}",
            key.unwrap_or("?"),
            name,
            score,
        ));
    }

    Value::String(s)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn do_redact(pii_type: &str, template: &str, summary: &mut RedactSummary) -> Value {
    summary.redacted += 1;
    summary.types.insert(pii_type.to_string());
    Value::String(template.replace("{type}", pii_type))
}

/// True if `s` already looks like a redaction placeholder produced by `template`.
fn is_redaction_placeholder(s: &str, template: &str) -> bool {
    match template.split_once("{type}") {
        Some((prefix, suffix)) => {
            s.starts_with(prefix) && s.ends_with(suffix) && s.len() > prefix.len() + suffix.len()
        }
        None => false,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PiiConfig;
    use serde_json::json;

    fn cfg() -> PiiConfig {
        PiiConfig::default()
    }

    fn cfg_no_summary() -> PiiConfig {
        PiiConfig {
            include_summary: false,
            ..PiiConfig::default()
        }
    }

    fn plan() -> RedactPlan {
        RedactPlan::empty()
    }

    // ── 1. tkpsql object shape ────────────────────────────────────────────────

    #[test]
    fn tkpsql_object_shape_redacts_and_attaches_summary() {
        let input = json!({
            "rows": [{"id": 1, "email": "alice@example.com", "ssn": "123-45-6789"}],
            "count": 1
        });
        let out = redact(input, &plan(), &cfg());
        let rows = &out["rows"][0];
        assert_eq!(rows["id"], 1);
        assert_eq!(rows["email"], "[PII:email]");
        assert_eq!(rows["ssn"], "[PII:ssn]");
        assert_eq!(out["count"], 1);
        assert_eq!(out["_gate_summary"]["redacted"], 2);
        let types = out["_gate_summary"]["types"].as_array().unwrap();
        assert!(types.contains(&json!("email")));
        assert!(types.contains(&json!("ssn")));
    }

    // ── 2. Bare array + include_summary = true → wrapped ─────────────────────

    #[test]
    fn bare_array_with_summary_wraps_into_rows() {
        let input = json!([{"id": 1, "email": "bob@example.com"}]);
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["rows"][0]["email"], "[PII:email]");
        assert_eq!(out["rows"][0]["id"], 1);
        assert_eq!(out["_gate_summary"]["redacted"], 1);
    }

    // ── 3. Bare array + include_summary = false → shape preserved ─────────────

    #[test]
    fn bare_array_without_summary_preserves_shape() {
        let input = json!([{"id": 1, "email": "bob@example.com"}]);
        let out = redact(input, &plan(), &cfg_no_summary());
        assert!(out.is_array());
        assert_eq!(out[0]["email"], "[PII:email]");
        assert!(out[0].get("_gate_summary").is_none());
    }

    // ── 4. Error pass-through ─────────────────────────────────────────────────

    #[test]
    fn error_shape_passes_through_unchanged() {
        let input = json!({"error": "permission denied"});
        let out = redact(input.clone(), &plan(), &cfg());
        assert_eq!(out, input);
        assert!(out.get("_gate_summary").is_none());
    }

    #[test]
    fn error_shape_with_pii_in_message_still_passes_through() {
        // Gate 2 must not scan error payloads at all.
        let input = json!({"error": "user alice@example.com not found"});
        let out = redact(input.clone(), &plan(), &cfg());
        assert_eq!(out, input);
    }

    // ── 5. JSONB column (nested JSON string) ──────────────────────────────────

    #[test]
    fn jsonb_column_is_scanned_recursively() {
        let input = json!({"id": 1, "profile": "{\"email\": \"alice@example.com\"}"});
        let out = redact(input, &plan(), &cfg());
        let profile_str = out["profile"].as_str().unwrap();
        let profile: Value = serde_json::from_str(profile_str).unwrap();
        assert_eq!(profile["email"], "[PII:email]");
        assert_eq!(out["_gate_summary"]["redacted"], 1);
    }

    #[test]
    fn jsonb_with_no_pii_is_returned_unchanged() {
        let input = json!({"meta": "{\"count\": 5, \"status\": \"ok\"}"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["meta"], "{\"count\": 5, \"status\": \"ok\"}");
        assert_eq!(out["_gate_summary"]["redacted"], 0);
    }

    // ── 6. Null values in PII-named columns ──────────────────────────────────

    #[test]
    fn null_in_pii_column_passes_through() {
        let input = json!({"email": null, "ssn": null, "id": 1});
        let out = redact(input, &plan(), &cfg());
        assert!(out["email"].is_null());
        assert!(out["ssn"].is_null());
        assert_eq!(out["_gate_summary"]["redacted"], 0);
    }

    // ── 7. Forced column from Gate 1 plan ─────────────────────────────────────

    #[test]
    fn forced_column_redacts_regardless_of_content() {
        let mut p = plan();
        p.forced_columns
            .insert("contact".to_string(), "email".to_string());
        // Value doesn't match the email regex, but forced column must win.
        let input = json!({"contact": "not-an-email-at-all", "id": 1});
        let out = redact(input, &p, &cfg());
        assert_eq!(out["contact"], "[PII:email]");
        assert_eq!(out["id"], 1);
        assert_eq!(out["_gate_summary"]["redacted"], 1);
    }

    #[test]
    fn forced_column_merges_gate1_warnings_into_summary() {
        let mut p = plan();
        p.warnings
            .push("SELECT * encountered, wildcard_policy=warn".to_string());
        let input = json!({"id": 1});
        let out = redact(input, &p, &cfg());
        let warnings = out["_gate_summary"]["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].as_str().unwrap().contains("wildcard_policy"));
    }

    // ── 8. Low-confidence match: warned but not redacted ─────────────────────

    #[test]
    fn low_confidence_phone_in_generic_column_is_warned_not_redacted() {
        // phone base confidence = 0.70; default threshold = 0.80; "notes" is not a PII column.
        let input = json!({"notes": "555-123-4567"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["notes"], "555-123-4567");
        assert_eq!(out["_gate_summary"]["redacted"], 0);
        let warnings = out["_gate_summary"]["warnings"].as_array().unwrap();
        assert!(!warnings.is_empty(), "expected a low-confidence warning");
    }

    // ── 9. Luhn-pass in non-PII column ───────────────────────────────────────

    #[test]
    fn luhn_valid_string_always_redacted_regardless_of_column() {
        let input = json!({"order_id": "4111111111111111"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["order_id"], "[PII:credit_card]");
        assert_eq!(out["_gate_summary"]["redacted"], 1);
    }

    #[test]
    fn luhn_valid_with_spaces_redacted() {
        let input = json!({"ref": "4111 1111 1111 1111"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["ref"], "[PII:credit_card]");
    }

    // ── 10. Luhn-fail: 16-digit non-card string not redacted ─────────────────

    #[test]
    fn luhn_invalid_16_digit_string_passes_through() {
        // 1234567890123456 fails Luhn and has no other pattern match.
        let input = json!({"order_id": "1234567890123456"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["order_id"], "1234567890123456");
    }

    // ── 11. Idempotency ───────────────────────────────────────────────────────

    #[test]
    fn redaction_is_idempotent() {
        // Data values must be stable on a second pass; placeholders are not re-redacted.
        // Summary counts will differ (second pass sees 0 new redactions) — that is expected.
        let input = json!({
            "rows": [{"id": 1, "email": "alice@example.com", "ssn": "111-22-3333"}],
            "count": 1
        });
        let first = redact(input, &plan(), &cfg());
        let second = redact(first.clone(), &plan(), &cfg());
        assert_eq!(first["rows"][0]["email"], second["rows"][0]["email"]);
        assert_eq!(first["rows"][0]["ssn"], second["rows"][0]["ssn"]);
        assert_eq!(first["rows"][0]["id"], second["rows"][0]["id"]);
        assert_eq!(first["rows"][0]["email"], "[PII:email]");
        assert_eq!(first["rows"][0]["ssn"], "[PII:ssn]");
    }

    // ── 12. Token-based column name matching ──────────────────────────────────

    #[test]
    fn camel_case_column_triggers_force_redact() {
        let input = json!({"userEmail": "alice@example.com", "id": 1});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["userEmail"], "[PII:email]");
        assert_eq!(out["id"], 1);
    }

    #[test]
    fn underscore_separated_pii_column_redacted() {
        let input = json!({"phone_number": "555-123-4567", "first_name": "Alice"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["phone_number"], "[PII:phone]");
        assert_eq!(out["first_name"], "[PII:name]");
    }

    #[test]
    fn synonym_column_names_are_classified() {
        // "mobile" → phone, "mail" → email
        let input = json!({"mobile": "555-123-4567", "mail": "alice@example.com"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["mobile"], "[PII:phone]");
        assert_eq!(out["mail"], "[PII:email]");
    }

    #[test]
    fn non_pii_name_token_not_triggered() {
        // "product_name" must not be redacted — bigram "productname" is not in synonyms.
        let input = json!({"product_name": "Widget Pro", "category_name": "Tools"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["product_name"], "Widget Pro");
        assert_eq!(out["category_name"], "Tools");
        assert_eq!(out["_gate_summary"]["redacted"], 0);
    }

    // ── 13. Multiple PII types in one payload ─────────────────────────────────

    #[test]
    fn multiple_pii_types_tracked_in_summary() {
        let input = json!({
            "email": "alice@example.com",
            "ssn": "123-45-6789",
            "card": "4111111111111111"
        });
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["_gate_summary"]["redacted"], 3);
        let types = out["_gate_summary"]["types"].as_array().unwrap();
        let type_strs: Vec<&str> = types.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(type_strs.contains(&"email"));
        assert!(type_strs.contains(&"ssn"));
        assert!(type_strs.contains(&"credit_card"));
    }

    // ── 14. Custom redaction template ─────────────────────────────────────────

    #[test]
    fn custom_redaction_template_is_used() {
        let config = PiiConfig {
            redaction: "[REDACTED:{type}]".to_string(),
            ..PiiConfig::default()
        };
        let input = json!({"email": "alice@example.com"});
        let out = redact(input, &plan(), &config);
        assert_eq!(out["email"], "[REDACTED:email]");
    }

    // ── 15. Column order preserved (preserve_order feature) ───────────────────

    #[test]
    fn column_order_preserved_in_output() {
        let input = json!({"z_col": "last", "a_col": "first", "email": "alice@example.com"});
        let out = redact(input, &plan(), &cfg());
        if let Value::Object(map) = &out {
            let keys: Vec<&str> = map.keys().map(String::as_str).collect();
            // Original order must be preserved; _gate_summary appended last.
            assert_eq!(keys[0], "z_col");
            assert_eq!(keys[1], "a_col");
            assert_eq!(keys[2], "email");
            assert_eq!(keys[3], "_gate_summary");
        } else {
            panic!("expected object");
        }
    }
}
