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
    /// When true, Gate 2 prints per-field redaction decisions to stderr.
    pub verbose: bool,
}

impl RedactPlan {
    pub fn empty() -> Self {
        Self {
            forced_columns: HashMap::new(),
            warnings: Vec::new(),
            rejected: false,
            verbose: false,
        }
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

/// Candidate key names for the column-headers array (all-strings).
const COL_KEYS: &[&str] = &["columns", "headers", "keys", "fields"];
/// Candidate key names for the data-rows array (all-arrays).
const ROW_KEYS: &[&str] = &["rows", "records", "results", "data"];

#[derive(PartialEq)]
enum Shape {
    Error,
    /// Object with an all-strings column-header array and an all-arrays row array.
    /// Carries the detected field names so redact_columnar doesn't re-scan.
    Columnar {
        col_field: &'static str,
        row_field: &'static str,
    },
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
    let effective_allowlist = config.effective_column_allowlist();
    let mut summary = RedactSummary::new();

    let redacted_payload = if let Shape::Columnar {
        col_field,
        row_field,
    } = &shape
    {
        redact_columnar(
            payload,
            col_field,
            row_field,
            plan,
            config,
            &patterns,
            &effective_names,
            &effective_allowlist,
            &mut summary,
        )
    } else {
        walk(
            payload,
            None,
            plan,
            config,
            &patterns,
            &effective_names,
            &effective_allowlist,
            &mut summary,
        )
    };

    for w in &plan.warnings {
        summary.warnings.push(w.clone());
    }

    apply_summary(redacted_payload, &summary, config.include_summary, &shape)
}

// ── Shape detection ───────────────────────────────────────────────────────────

/// Scan the map for a columnar shape using any of the accepted alias key names.
/// Returns `(col_field, row_field)` on success.
fn find_columnar_keys(map: &Map<String, Value>) -> Option<(&'static str, &'static str)> {
    let col_field = COL_KEYS.iter().copied().find(|&k| {
        map.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().all(|v| v.is_string()))
            .unwrap_or(false)
    })?;
    let row_field = ROW_KEYS.iter().copied().find(|&k| {
        map.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().all(|v| v.is_array()))
            .unwrap_or(false)
    })?;
    Some((col_field, row_field))
}

fn detect_shape(val: &Value) -> Shape {
    match val {
        Value::Object(map) => match map.get("error") {
            Some(Value::String(s)) if !s.is_empty() => Shape::Error,
            _ => {
                if let Some((col_field, row_field)) = find_columnar_keys(map) {
                    Shape::Columnar {
                        col_field,
                        row_field,
                    }
                } else {
                    Shape::Object
                }
            }
        },
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
        Shape::Object | Shape::Columnar { .. } => {
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

// ── Columnar redaction ────────────────────────────────────────────────────────

/// Redact a columnar payload `{<col_field>:[...], <row_field>:[[...]]}`.
/// Each value in every row array is scanned using its positional column name.
/// All other top-level fields (e.g. "count") are walked normally.
#[allow(clippy::too_many_arguments)]
fn redact_columnar(
    payload: Value,
    col_field: &str,
    row_field: &str,
    plan: &RedactPlan,
    config: &PiiConfig,
    patterns: &[CompiledPattern],
    effective_names: &[String],
    effective_allowlist: &[String],
    summary: &mut RedactSummary,
) -> Value {
    let Value::Object(mut map) = payload else {
        unreachable!("columnar shape is always an object");
    };

    // Extract the column header names (already validated as strings by detect_shape).
    let col_names: Vec<String> = map
        .get(col_field)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();

    // Redact the rows array-of-arrays positionally.
    if let Some(Value::Array(rows)) = map.remove(row_field) {
        let new_rows: Vec<Value> = rows
            .into_iter()
            .map(|row| {
                if let Value::Array(cells) = row {
                    Value::Array(
                        cells
                            .into_iter()
                            .enumerate()
                            .map(|(i, cell)| {
                                let col_name = col_names.get(i).map(String::as_str);
                                walk(
                                    cell,
                                    col_name,
                                    plan,
                                    config,
                                    patterns,
                                    effective_names,
                                    effective_allowlist,
                                    summary,
                                )
                            })
                            .collect(),
                    )
                } else {
                    // Non-array row: walk without column context
                    walk(
                        row,
                        None,
                        plan,
                        config,
                        patterns,
                        effective_names,
                        effective_allowlist,
                        summary,
                    )
                }
            })
            .collect();
        map.insert(row_field.to_string(), Value::Array(new_rows));
    }

    // Walk all other top-level fields normally (e.g. "count", col_field itself).
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
                effective_allowlist,
                summary,
            );
            (k, new_v)
        })
        .collect();

    Value::Object(new_map)
}

// ── Tree walk ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn walk(
    val: Value,
    key: Option<&str>,
    plan: &RedactPlan,
    config: &PiiConfig,
    patterns: &[CompiledPattern],
    effective_names: &[String],
    effective_allowlist: &[String],
    summary: &mut RedactSummary,
) -> Value {
    match val {
        Value::String(s) => scan_string(
            s,
            key,
            plan,
            config,
            patterns,
            effective_names,
            effective_allowlist,
            summary,
        ),
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
                        effective_allowlist,
                        summary,
                    );
                    (k, new_v)
                })
                .collect();
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(|v| {
                    walk(
                        v,
                        key,
                        plan,
                        config,
                        patterns,
                        effective_names,
                        effective_allowlist,
                        summary,
                    )
                })
                .collect(),
        ),
        other => other,
    }
}

// ── Per-value scanner ─────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn scan_string(
    s: String,
    key: Option<&str>,
    plan: &RedactPlan,
    config: &PiiConfig,
    patterns: &[CompiledPattern],
    effective_names: &[String],
    effective_allowlist: &[String],
    summary: &mut RedactSummary,
) -> Value {
    let vb = plan.verbose;
    let kname = key.unwrap_or("?");

    // Idempotency: skip already-redacted placeholders so a second pass doesn't
    // inflate the summary count.
    if is_redaction_placeholder(&s, &config.redaction) {
        return Value::String(s);
    }

    let key_lower = key.map(|k| k.to_lowercase());

    // Allowlist check: if the column name is explicitly allowlisted, skip all
    // name-based redaction steps (1–3). Value-based checks (Luhn, regex) still apply.
    let is_allowlisted = key_lower
        .as_deref()
        .map(|k| effective_allowlist.iter().any(|a| a == k))
        .unwrap_or(false);

    if !is_allowlisted {
        // 1. Gate 1 forced columns (keys are pre-lowercased by Gate 1).
        if let Some(ref k) = key_lower {
            if let Some(type_label) = plan.forced_columns.get(k.as_str()) {
                if vb {
                    eprintln!(
                        "[gate] field {:?} → REDACTED (step: forced_column, type: {})",
                        kname, type_label
                    );
                }
                return do_redact(type_label, &s, config, summary);
            }
        }

        // 2. Token-based column classification — catches camelCase, synonyms, etc.
        //    Force-redacts any value under a PII-named key, regardless of content.
        if let Some(k) = key {
            if let Some(pii_type) = classify_column(k) {
                if vb {
                    eprintln!(
                        "[gate] field {:?} → REDACTED (step: column_classify, type: {})",
                        kname, pii_type
                    );
                }
                return do_redact(pii_type, &s, config, summary);
            }
        }

        // 3. Exact match against the effective column-name list.
        //    Covers user-supplied column names not handled by the synonym table.
        if let Some(ref k) = key_lower {
            if effective_names.iter().any(|n| n == k) {
                if vb {
                    eprintln!(
                        "[gate] field {:?} → REDACTED (step: column_name_exact, type: {})",
                        kname, k
                    );
                }
                return do_redact(k.as_str(), &s, config, summary);
            }
        }
    } else if vb {
        eprintln!(
            "[gate] field {:?} → skipping name-based checks (allowlisted)",
            kname
        );
    }

    // 4. JSONB: if the value is a serialised JSON object or array, scan it recursively.
    if let Ok(inner) = serde_json::from_str::<Value>(&s) {
        if matches!(inner, Value::Object(_) | Value::Array(_)) {
            let count_before = summary.redacted;
            let walked = walk(
                inner,
                key,
                plan,
                config,
                patterns,
                effective_names,
                effective_allowlist,
                summary,
            );
            if summary.redacted > count_before {
                if vb {
                    eprintln!(
                        "[gate] field {:?} (jsonb) → REDACTED ({} field(s) inside)",
                        kname,
                        summary.redacted - count_before
                    );
                }
                return Value::String(serde_json::to_string(&walked).unwrap_or(s));
            }
            return Value::String(s);
        }
    }

    // 5. Luhn check — always redacts Luhn-valid card-shaped strings.
    if Luhn::check(&s) {
        if vb {
            eprintln!(
                "[gate] field {:?} → REDACTED (step: luhn, type: credit_card)",
                kname
            );
        }
        return do_redact("credit_card", &s, config, summary);
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
            if vb {
                eprintln!(
                    "[gate] field {:?} → REDACTED (step: regex, pattern: {}, score: {:.2})",
                    kname, name, score
                );
            }
            return do_redact(name, &s, config, summary);
        }
        if vb {
            eprintln!(
                "[gate] field {:?} → warned (step: regex, pattern: {}, score: {:.2} < threshold: {:.2})",
                kname,
                name,
                score,
                config.confidence_threshold
            );
        }
        summary.warnings.push(format!(
            "low-confidence match: key={} pattern={} score={:.2}",
            key.unwrap_or("?"),
            name,
            score,
        ));
    } else if vb {
        eprintln!("[gate] field {:?} → passed (no match)", kname);
    }

    Value::String(s)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn do_redact(
    pii_type: &str,
    original: &str,
    config: &PiiConfig,
    summary: &mut RedactSummary,
) -> Value {
    summary.redacted += 1;
    summary.types.insert(pii_type.to_string());
    let type_token = if config.hash_values {
        let h = hash_value(&config.hash_salt, original);
        format!("{}:{}", pii_type, h)
    } else {
        pii_type.to_string()
    };
    Value::String(config.redaction.replace("{type}", &type_token))
}

/// FNV-1a 64-bit, XOR-folded to 32 bits for an 8-char hex output.
/// A null-byte separator between salt and value prevents `hash("ab","c") == hash("a","bc")`.
fn hash_value(salt: &str, value: &str) -> String {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let mut h = FNV_OFFSET;
    for byte in salt
        .bytes()
        .chain(std::iter::once(0u8))
        .chain(value.bytes())
    {
        h ^= byte as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    let folded = (h ^ (h >> 32)) as u32;
    format!("{:08x}", folded)
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

    #[test]
    fn null_error_key_is_not_error_shape() {
        // {"error": null, "rows": [...]} is a common success envelope — must not bypass Gate 2.
        let input = json!({"error": null, "rows": [{"email": "alice@example.com"}]});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["rows"][0]["email"], "[PII:email]");
    }

    #[test]
    fn false_error_key_is_not_error_shape() {
        let input = json!({"error": false, "email": "alice@example.com"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["email"], "[PII:email]");
    }

    #[test]
    fn empty_string_error_key_is_not_error_shape() {
        let input = json!({"error": "", "email": "alice@example.com"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["email"], "[PII:email]");
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

    // ── 16. Deterministic hashing ─────────────────────────────────────────────

    // ── hash_value unit tests ────────────────────────────────────────────────

    #[test]
    fn hash_value_always_8_lowercase_hex() {
        for (salt, val) in [
            ("", ""),
            ("", "alice@example.com"),
            ("secret", "123-45-6789"),
            ("a", "b"),
            ("long-salt-value", "4111111111111111"),
        ] {
            let h = hash_value(salt, val);
            assert_eq!(h.len(), 8, "salt={salt:?} val={val:?} → {h}");
            assert!(
                h.chars().all(|c| c.is_ascii_hexdigit()),
                "non-hex char in {h}"
            );
            assert_eq!(h, h.to_lowercase(), "must be lowercase");
        }
    }

    #[test]
    fn hash_value_same_inputs_same_output() {
        assert_eq!(
            hash_value("salt", "alice@example.com"),
            hash_value("salt", "alice@example.com")
        );
    }

    #[test]
    fn hash_value_different_values_different_output() {
        assert_ne!(
            hash_value("salt", "alice@example.com"),
            hash_value("salt", "bob@example.com")
        );
    }

    #[test]
    fn hash_value_salt_changes_output() {
        let v = "alice@example.com";
        assert_ne!(hash_value("salt-a", v), hash_value("salt-b", v));
    }

    #[test]
    fn hash_value_empty_salt_valid() {
        let h = hash_value("", "alice@example.com");
        assert_eq!(h.len(), 8);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_value_salt_prefix_not_same_as_concatenation() {
        // hash("ab", "c") must differ from hash("a", "bc") to prevent salt-stripping attacks.
        assert_ne!(hash_value("ab", "c"), hash_value("a", "bc"));
    }

    fn cfg_hash() -> PiiConfig {
        PiiConfig {
            hash_values: true,
            hash_salt: "test-salt".to_string(),
            ..PiiConfig::default()
        }
    }

    #[test]
    fn hash_mode_appends_8_hex_chars() {
        let input = json!({"email": "alice@example.com"});
        let out = redact(input, &plan(), &cfg_hash());
        let val = out["email"].as_str().unwrap();
        assert!(val.starts_with("[PII:email:"), "got: {val}");
        let hash_part = val
            .strip_prefix("[PII:email:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();
        assert_eq!(hash_part.len(), 8);
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_mode_is_deterministic_same_value_same_hash() {
        let cfg = cfg_hash();
        let out1 = redact(json!({"email": "alice@example.com"}), &plan(), &cfg);
        let out2 = redact(json!({"email": "alice@example.com"}), &plan(), &cfg);
        assert_eq!(out1["email"], out2["email"]);
    }

    #[test]
    fn hash_mode_different_values_produce_different_hashes() {
        let cfg = cfg_hash();
        let out1 = redact(json!({"email": "alice@example.com"}), &plan(), &cfg);
        let out2 = redact(json!({"email": "bob@example.com"}), &plan(), &cfg);
        assert_ne!(out1["email"], out2["email"]);
    }

    #[test]
    fn hash_mode_same_value_same_hash_across_columns() {
        // Two columns with the same raw value should produce the same hash suffix,
        // enabling cross-column joins.
        let cfg = cfg_hash();
        let input = json!({"email": "alice@example.com", "user_email": "alice@example.com"});
        let out = redact(input, &plan(), &cfg);
        let e = out["email"].as_str().unwrap();
        let ue = out["user_email"].as_str().unwrap();
        // Strip the type prefix to compare just the hash part.
        let e_hash = e.split(':').next_back().unwrap().trim_end_matches(']');
        let ue_hash = ue.split(':').next_back().unwrap().trim_end_matches(']');
        assert_eq!(e_hash, ue_hash, "same value must hash identically");
    }

    #[test]
    fn hash_mode_different_salts_produce_different_hashes() {
        let cfg1 = PiiConfig {
            hash_values: true,
            hash_salt: "salt-a".to_string(),
            ..PiiConfig::default()
        };
        let cfg2 = PiiConfig {
            hash_values: true,
            hash_salt: "salt-b".to_string(),
            ..PiiConfig::default()
        };
        let out1 = redact(json!({"email": "alice@example.com"}), &plan(), &cfg1);
        let out2 = redact(json!({"email": "alice@example.com"}), &plan(), &cfg2);
        assert_ne!(out1["email"], out2["email"]);
    }

    #[test]
    fn hash_mode_placeholder_is_idempotent() {
        // A hashed placeholder must not be re-hashed on a second redact pass.
        let cfg = cfg_hash();
        let input = json!({"email": "alice@example.com"});
        let first = redact(input, &plan(), &cfg);
        let second = redact(first.clone(), &plan(), &cfg);
        assert_eq!(first["email"], second["email"]);
    }

    #[test]
    fn hash_mode_works_with_custom_template() {
        let cfg = PiiConfig {
            hash_values: true,
            hash_salt: "s".to_string(),
            redaction: "[REDACTED:{type}]".to_string(),
            ..PiiConfig::default()
        };
        let input = json!({"email": "alice@example.com"});
        let out = redact(input, &plan(), &cfg);
        let val = out["email"].as_str().unwrap();
        assert!(val.starts_with("[REDACTED:email:"), "got: {val}");
        assert!(val.ends_with(']'));
    }

    #[test]
    fn hash_mode_off_by_default() {
        let input = json!({"email": "alice@example.com"});
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["email"], "[PII:email]");
    }

    #[test]
    fn hash_mode_luhn_value_is_hashed() {
        let cfg = cfg_hash();
        let input = json!({"order_id": "4111111111111111"});
        let out = redact(input, &plan(), &cfg);
        let val = out["order_id"].as_str().unwrap();
        assert!(val.starts_with("[PII:credit_card:"), "got: {val}");
    }

    #[test]
    fn hash_mode_summary_types_are_bare_names() {
        // _gate_summary.types must list the PII type ("email"), not the hash-suffixed token.
        let cfg = cfg_hash();
        let input = json!({"email": "alice@example.com", "ssn": "123-45-6789"});
        let out = redact(input, &plan(), &cfg);
        let types = out["_gate_summary"]["types"].as_array().unwrap();
        let type_strs: Vec<&str> = types.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(type_strs.contains(&"email"), "got: {type_strs:?}");
        assert!(type_strs.contains(&"ssn"), "got: {type_strs:?}");
        // No hash suffix in the type list.
        for t in &type_strs {
            assert!(!t.contains(':'), "type should not contain ':': {t}");
        }
    }

    #[test]
    fn hash_mode_forced_column_value_is_hashed() {
        // Gate 1 forced-column path (scan_string step 1): value is hashed.
        let mut p = plan();
        p.forced_columns
            .insert("contact".to_string(), "email".to_string());
        let cfg = cfg_hash();
        let input = json!({"contact": "not-an-email-at-all"});
        let out = redact(input, &p, &cfg);
        let val = out["contact"].as_str().unwrap();
        assert!(val.starts_with("[PII:email:"), "got: {val}");
        let hash_part = val
            .strip_prefix("[PII:email:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();
        assert_eq!(hash_part.len(), 8);
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_mode_jsonb_inner_values_hashed() {
        // JSONB scan path (scan_string step 4): inner values are hashed.
        let cfg = cfg_hash();
        let input = json!({"profile": "{\"email\": \"alice@example.com\"}"});
        let out = redact(input, &plan(), &cfg);
        let profile_str = out["profile"].as_str().unwrap();
        let profile: Value = serde_json::from_str(profile_str).unwrap();
        let val = profile["email"].as_str().unwrap();
        assert!(val.starts_with("[PII:email:"), "got: {val}");
        assert_eq!(out["_gate_summary"]["redacted"], 1);
    }

    // ── 19. Allowlist ─────────────────────────────────────────────────────────

    fn cfg_allowlist(columns: &[&str]) -> PiiConfig {
        PiiConfig {
            column_allowlist: columns.iter().map(|s| s.to_string()).collect(),
            ..PiiConfig::default()
        }
    }

    #[test]
    fn allowlisted_column_passes_through_name_check() {
        // "city" normally triggers address redaction; with allowlist it should pass through.
        let config = cfg_allowlist(&["city"]);
        let input = json!({"city": "Wellington", "email": "alice@example.com"});
        let out = redact(input, &plan(), &config);
        assert_eq!(out["city"], "Wellington");
        assert_eq!(out["email"], "[PII:email]");
        assert_eq!(out["_gate_summary"]["redacted"], 1);
    }

    #[test]
    fn allowlist_is_case_insensitive() {
        let config = cfg_allowlist(&["City"]);
        let input = json!({"city": "Auckland"});
        let out = redact(input, &plan(), &config);
        assert_eq!(out["city"], "Auckland");
    }

    #[test]
    fn allowlisted_column_still_redacts_luhn_value() {
        // Even if the column is allowlisted, a Luhn-valid CC number must still be redacted.
        let config = cfg_allowlist(&["bank_code"]);
        let input = json!({"bank_code": "4111111111111111"});
        let out = redact(input, &plan(), &config);
        assert_eq!(out["bank_code"], "[PII:credit_card]");
    }

    #[test]
    fn allowlisted_column_still_redacts_regex_match() {
        // A high-confidence SSN in an allowlisted column must still be caught by regex.
        let config = cfg_allowlist(&["ref_code"]);
        let input = json!({"ref_code": "123-45-6789"});
        let out = redact(input, &plan(), &config);
        assert_eq!(out["ref_code"], "[PII:ssn]");
    }

    #[test]
    fn allowlist_overrides_forced_column_from_gate1() {
        let mut p = plan();
        p.forced_columns
            .insert("city".to_string(), "address".to_string());
        let config = cfg_allowlist(&["city"]);
        let input = json!({"city": "Wellington"});
        let out = redact(input, &p, &config);
        assert_eq!(out["city"], "Wellington");
    }

    #[test]
    fn non_allowlisted_columns_still_redacted() {
        let config = cfg_allowlist(&["postcode"]);
        let input = json!({"postcode": "1010", "street": "123 Main St"});
        let out = redact(input, &plan(), &config);
        assert_eq!(out["postcode"], "1010");
        assert_eq!(out["street"], "[PII:address]");
    }

    #[test]
    fn hash_mode_empty_salt_produces_valid_hash() {
        let cfg = PiiConfig {
            hash_values: true,
            hash_salt: String::new(),
            ..PiiConfig::default()
        };
        let out = redact(json!({"email": "alice@example.com"}), &plan(), &cfg);
        let val = out["email"].as_str().unwrap();
        assert!(val.starts_with("[PII:email:"), "got: {val}");
        let hash_part = val
            .strip_prefix("[PII:email:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();
        assert_eq!(hash_part.len(), 8);
    }

    #[test]
    fn hash_mode_regex_path_value_is_hashed() {
        // Regex scan path (scan_string step 6): SSN matched by pattern, value is hashed.
        let cfg = cfg_hash();
        let input = json!({"data": "123-45-6789"});
        let out = redact(input, &plan(), &cfg);
        let val = out["data"].as_str().unwrap();
        assert!(val.starts_with("[PII:ssn:"), "got: {val}");
    }

    // ── 17. Columnar shape {columns:[...], rows:[[...]]} ─────────────────────

    #[test]
    fn columnar_shape_redacts_pii_columns_by_position() {
        let input = json!({
            "columns": ["client_id", "first_names", "last_name", "date_of_birth"],
            "count": 2,
            "rows": [
                ["37a7c4c8-d55b-4a4a-a47f-778ceabbfbaa", "Alice", "Smith", "1990-01-01"],
                ["86eb7438-677f-45a2-bbe6-eca90f502966", "Bob Jones", "Taylor", null]
            ]
        });
        let out = redact(input, &plan(), &cfg());
        // client_id → id (now classified as a person identifier)
        assert_eq!(out["rows"][0][0], "[PII:id]");
        // first_names → name
        assert_eq!(out["rows"][0][1], "[PII:name]");
        // last_name → name
        assert_eq!(out["rows"][0][2], "[PII:name]");
        // date_of_birth → dob
        assert_eq!(out["rows"][0][3], "[PII:dob]");
        // second row
        assert_eq!(out["rows"][1][0], "[PII:id]");
        assert_eq!(out["rows"][1][1], "[PII:name]");
        assert_eq!(out["rows"][1][2], "[PII:name]");
        // null stays null
        assert!(out["rows"][1][3].is_null());
        // summary: 4 in row 0 + 3 non-null in row 1 = 7
        assert_eq!(out["_gate_summary"]["redacted"], 7);
    }

    #[test]
    fn columnar_shape_non_pii_columns_pass_through() {
        let input = json!({
            "columns": ["id", "status", "amount"],
            "rows": [["1", "active", "99.99"]]
        });
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["rows"][0][0], "1");
        assert_eq!(out["rows"][0][1], "active");
        assert_eq!(out["rows"][0][2], "99.99");
        assert_eq!(out["_gate_summary"]["redacted"], 0);
    }

    #[test]
    fn columnar_shape_preserves_count_and_columns_fields() {
        let input = json!({
            "columns": ["email"],
            "count": 1,
            "rows": [["alice@example.com"]]
        });
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["count"], 1);
        // columns array itself is preserved
        assert_eq!(out["columns"][0], "email");
        assert_eq!(out["rows"][0][0], "[PII:email]");
    }

    #[test]
    fn columnar_shape_empty_rows_ok() {
        let input = json!({
            "columns": ["email", "ssn"],
            "rows": []
        });
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["_gate_summary"]["redacted"], 0);
        assert!(out["rows"].as_array().unwrap().is_empty());
    }

    #[test]
    fn columnar_shape_with_existing_gate_summary_replaced() {
        // The input already has a _gate_summary (e.g. piped from a tool) — our new
        // summary must replace it correctly.
        let input = json!({
            "columns": ["first_names", "last_name"],
            "rows": [["Gary", "Zhu"]],
            "_gate_summary": {"redacted": 0, "types": [], "warnings": []}
        });
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["rows"][0][0], "[PII:name]");
        assert_eq!(out["rows"][0][1], "[PII:name]");
        assert_eq!(out["_gate_summary"]["redacted"], 2);
    }

    #[test]
    fn columnar_shape_object_rows_not_detected_as_columnar() {
        // rows with objects → not columnar shape; falls back to normal Object walk.
        let input = json!({
            "columns": ["email"],
            "rows": [{"email": "alice@example.com"}]
        });
        // rows[0] is an object, so it should NOT be treated as columnar.
        // The email key inside the object row WILL be matched by column classification.
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["rows"][0]["email"], "[PII:email]");
    }

    // ── 18. Columnar alias key names ─────────────────────────────────────────

    #[test]
    fn columnar_alias_headers_records() {
        let input = json!({
            "headers": ["email", "id"],
            "records": [["alice@example.com", "1"], ["bob@example.com", "2"]]
        });
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["records"][0][0], "[PII:email]");
        assert_eq!(out["records"][0][1], "1");
        assert_eq!(out["records"][1][0], "[PII:email]");
        assert_eq!(out["headers"][0], "email");
        assert_eq!(out["_gate_summary"]["redacted"], 2);
    }

    #[test]
    fn columnar_alias_keys_results() {
        let input = json!({
            "keys": ["ssn", "first_name"],
            "results": [["123-45-6789", "Alice"]]
        });
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["results"][0][0], "[PII:ssn]");
        assert_eq!(out["results"][0][1], "[PII:name]");
        assert_eq!(out["_gate_summary"]["redacted"], 2);
    }

    #[test]
    fn columnar_alias_fields_data() {
        let input = json!({
            "fields": ["email"],
            "data": [["alice@example.com"]]
        });
        let out = redact(input, &plan(), &cfg());
        assert_eq!(out["data"][0][0], "[PII:email]");
        assert_eq!(out["fields"][0], "email");
        assert_eq!(out["_gate_summary"]["redacted"], 1);
    }

    #[test]
    fn plain_object_not_mistaken_for_columnar() {
        // {"name": "gary"} has no col_field/row_field pair — must go through normal Object walk.
        let input = json!({"name": "gary"});
        let out = redact(input, &plan(), &cfg());
        // "name" alone is not a PII column trigger; value passes through unchanged.
        assert_eq!(out["name"], "gary");
        // No "rows" or "headers" key must be injected.
        assert!(out.get("rows").is_none());
        assert!(out.get("headers").is_none());
    }

    #[test]
    fn object_with_data_but_no_col_field_not_columnar() {
        // "data" alone (no matching all-strings column key) → Object walk, not columnar.
        let input = json!({"status": "ok", "data": [["a", "b"]]});
        let out = redact(input, &plan(), &cfg());
        // Processed as Object: data array contents are walked as-is (strings in arrays).
        assert_eq!(out["status"], "ok");
        assert_eq!(out["data"][0][0], "a");
    }
}
