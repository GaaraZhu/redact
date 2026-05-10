use std::collections::BTreeMap;
use std::io::Read;

use common::config::Config;
use common::error::exit_with_error;
use common::patterns::classify_column;

/// Tier 1 categories in the order they appear in the README.
const TIER1_CATEGORIES_ORDERED: &[&str] = &[
    "Names",
    "Demographics",
    "Government IDs",
    "Contact",
    "Date of birth",
    "Location of birth",
    "Address & location",
    "Financial",
    "Employment",
    "Health & medical",
    "Online & technical",
    "Biometric",
    "Family & relationships",
];

/// Run the scan subcommand: read columnar JSON from stdin and report PII-exposed column names.
///
/// Supports two input shapes:
/// 1. Array-of-arrays (tkdbr / tkmsql):
///    {"columns": ["TABLE_NAME", "COLUMN_NAME", ...], "rows": [["tbl", "col_name"], ...], ...}
/// 2. Array-of-objects (psql):
///    {"rows": [{"column_name": "col", "table_name": "tbl"}, ...], "count": N}
///
/// The subcommand extracts (table_name, column_name) pairs and runs Gate 1 column
/// classification on each column name.
pub fn run(verbose: bool) {
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => exit_with_error(&format!(
            "failed to load config: {e}. Run `gate config --init-only` to create a starter config."
        )),
    };

    // Read all of stdin
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        exit_with_error(&format!("failed to read stdin: {e}"));
    }

    // Parse JSON and extract (table_name, column_name) pairs
    let pairs = match parse_columnar_json(&input) {
        Ok(p) => p,
        Err(e) => exit_with_error(&e),
    };

    if pairs.is_empty() {
        println!("No columns found in input.");
        std::process::exit(0);
    }

    // Classify each column and aggregate results
    let stats = aggregate_by_category(&pairs, &config);

    // Render the report
    print_report(&pairs, &stats, verbose);

    // Exit code: 0 if no PII found, 1 if any PII columns detected
    let has_pii = stats.iter().any(|result| result.tier1 != "No PII");
    std::process::exit(if has_pii { 1 } else { 0 });
}

/// Parse columnar input to extract (table_name, column_name) pairs.
///
/// Supports three formats:
/// 1. Array-of-arrays (tkdbr / tkmsql): `{"columns": [...], "rows": [[...], ...]}`
///    Locates TABLE_NAME and COLUMN_NAME headers (case-insensitive) in the `columns` array,
///    then reads the corresponding positions from each row.
/// 2. Array-of-objects (psql JSON): `{"rows": [{"column_name": "...", "table_name": "..."}, ...]}`
///    Extracts column_name and table_name directly from each object.
/// 3. psql aligned text table (default `psql -c` output):
///    ```
///     table_name |  column_name
///    ------------+---------------
///     users      | id
///    (6 rows)
///    ```
fn parse_columnar_json(input: &str) -> Result<Vec<(String, String)>, String> {
    // Try JSON first (tkdbr array-of-arrays or psql array-of-objects format)
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input.trim()) {
        let rows = match value.get("rows") {
            Some(serde_json::Value::Array(r)) => r,
            _ => return Err(
                "unexpected input shape — expected a `rows` array (e.g. from tkdbr or psql query)."
                    .to_string(),
            ),
        };

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        return match &rows[0] {
            serde_json::Value::Array(_) => parse_array_of_arrays(&value, rows),
            serde_json::Value::Object(_) => parse_array_of_objects(rows),
            _ => Err(
                "unexpected row format — expected array of arrays (tkdbr) or array of objects (psql)."
                    .to_string(),
            ),
        };
    }

    // Fall back to psql aligned text table format
    if input.contains('|') {
        return parse_psql_text_table(input);
    }

    Err(
        "input is not valid JSON or psql table format — pipe the output of a schema query into gate scan."
            .to_string(),
    )
}

/// Parse psql aligned text table output:
/// ```text
///  table_name |  column_name
/// ------------+---------------
///  users      | id
/// (6 rows)
/// ```
fn parse_psql_text_table(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut lines = text.lines();

    // Find the header line (first line containing '|')
    let header_line = loop {
        match lines.next() {
            Some(line) if line.contains('|') => break line,
            Some(_) => continue,
            None => {
                return Err(
                    "no header line found in psql table output — expected table_name | column_name header."
                        .to_string(),
                )
            }
        }
    };

    // Parse header column names
    let headers: Vec<String> = header_line
        .split('|')
        .map(|h| h.trim().to_lowercase())
        .collect();

    let table_idx = headers.iter().position(|h| h == "table_name").ok_or_else(|| {
        "table_name column not found in psql output — query must include table_name and column_name."
            .to_string()
    })?;
    let column_idx = headers.iter().position(|h| h == "column_name").ok_or_else(|| {
        "column_name column not found in psql output — query must include table_name and column_name."
            .to_string()
    })?;

    // Skip the separator line (---+---)
    lines.next();

    // Parse data rows
    let mut pairs = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        // Stop at empty lines or the "(N rows)" footer
        if trimmed.is_empty() || (trimmed.starts_with('(') && trimmed.ends_with(')')) {
            break;
        }
        if !line.contains('|') {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(|c| c.trim()).collect();
        let table = cells.get(table_idx).copied().unwrap_or("").to_string();
        let col = cells.get(column_idx).copied().unwrap_or("").to_string();
        if !table.is_empty() && !col.is_empty() {
            pairs.push((table, col));
        }
    }

    Ok(pairs)
}

/// Parse array-of-arrays format: `{"columns": [...], "rows": [[...], ...]}`
fn parse_array_of_arrays(
    value: &serde_json::Value,
    rows: &[serde_json::Value],
) -> Result<Vec<(String, String)>, String> {
    // Extract columns array
    let columns = match value.get("columns") {
        Some(serde_json::Value::Array(cols)) => cols,
        _ => {
            return Err(
                "unexpected input shape — expected a `columns` array (e.g. from tkdbr query)."
                    .to_string(),
            )
        }
    };

    // Find the indices of TABLE_NAME and COLUMN_NAME (case-insensitive)
    let mut table_idx = None;
    let mut column_idx = None;

    for (i, col) in columns.iter().enumerate() {
        if let Some(col_str) = col.as_str() {
            match col_str.to_lowercase().as_str() {
                "table_name" => table_idx = Some(i),
                "column_name" => column_idx = Some(i),
                _ => {}
            }
        }
    }

    let table_idx = table_idx.ok_or_else(|| {
        "input is missing a TABLE_NAME column — query must include TABLE_NAME and COLUMN_NAME."
            .to_string()
    })?;

    let column_idx = column_idx.ok_or_else(|| {
        "input is missing a COLUMN_NAME column — query must include TABLE_NAME and COLUMN_NAME."
            .to_string()
    })?;

    // Collect (table, column) pairs
    let mut pairs = Vec::new();
    for row in rows {
        if let serde_json::Value::Array(row_arr) = row {
            if let (Some(table), Some(col)) = (row_arr.get(table_idx), row_arr.get(column_idx)) {
                if let (Some(table_str), Some(col_str)) = (table.as_str(), col.as_str()) {
                    pairs.push((table_str.to_string(), col_str.to_string()));
                }
            }
        }
    }

    Ok(pairs)
}

/// Parse array-of-objects format: `{"rows": [{"column_name": "...", "table_name": "..."}, ...]}`
fn parse_array_of_objects(rows: &[serde_json::Value]) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();

    for row in rows {
        if let serde_json::Value::Object(map) = row {
            // Extract column_name and table_name (case-insensitive key lookup)
            let mut column_name: Option<String> = None;
            let mut table_name: Option<String> = None;

            for (key, val) in map.iter() {
                match key.to_lowercase().as_str() {
                    "column_name" => {
                        if let Some(s) = val.as_str() {
                            column_name = Some(s.to_string());
                        }
                    }
                    "table_name" => {
                        if let Some(s) = val.as_str() {
                            table_name = Some(s.to_string());
                        }
                    }
                    _ => {}
                }
            }

            if let (Some(table), Some(col)) = (table_name, column_name) {
                pairs.push((table, col));
            }
        }
    }

    if pairs.is_empty() && !rows.is_empty() {
        return Err(
            "no valid (table_name, column_name) pairs found in objects — \
             each object must contain both fields."
                .to_string(),
        );
    }

    Ok(pairs)
}

/// Maps tier-2 PII categories to tier-1 categories for hierarchical reporting.
/// Based on README categories: Names, Demographics, Government IDs, Contact, etc.
fn map_to_tier1_category(tier2: &str) -> &'static str {
    match tier2 {
        // Names
        "name" => "Names",
        "salutation" => "Names",
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
        // Default
        _ => "Other",
    }
}

/// Aggregation result per PII category
struct TieredCategoryResult {
    tier1: &'static str,
    count: usize,
    examples: Vec<String>,
}

/// Classify each column using Gate 1 patterns and aggregate by tier-1 then tier-2 PII type.
fn aggregate_by_category(
    pairs: &[(String, String)],
    _config: &common::config::Config,
) -> Vec<TieredCategoryResult> {
    let mut map: BTreeMap<(String, String), TieredCategoryResult> = BTreeMap::new();

    for (table, col) in pairs {
        let tier2 = match classify_column(col) {
            Some(pii_type) => pii_type.to_string(),
            None => "No PII".to_string(),
        };

        let tier1 = if tier2 == "No PII" {
            "No PII"
        } else {
            map_to_tier1_category(&tier2)
        };

        let key = (tier1.to_string(), tier2.clone());
        let entry = map.entry(key).or_insert(TieredCategoryResult {
            tier1,
            count: 0,
            examples: Vec::new(),
        });

        entry.count += 1;

        // Store up to 3 examples
        if entry.examples.len() < 3 {
            entry.examples.push(format!("{}.{}", table, col));
        }
    }

    // Convert to vec sorted by tier1 then count descending
    let mut results: Vec<_> = map.into_values().collect();
    results.sort_by(|a, b| {
        // Sort "No PII" to the bottom
        match (a.tier1 == "No PII", b.tier1 == "No PII") {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => {
                // Within same tier1, sort by count descending
                a.tier1.cmp(b.tier1).then_with(|| b.count.cmp(&a.count))
            }
        }
    });

    results
}

/// Print the scan report to stdout.
fn print_report(pairs: &[(String, String)], stats: &[TieredCategoryResult], verbose: bool) {
    let total_columns = pairs.len();
    let unique_tables = pairs
        .iter()
        .map(|(t, _)| t)
        .collect::<std::collections::HashSet<_>>()
        .len();

    println!("\x1b[1mGate PII Scan\x1b[0m");
    println!("{}", "─".repeat(59));
    println!();

    // Summary section
    println!("\x1b[1mSummary\x1b[0m");

    // Separate PII from "No PII"
    let (pii_results, no_pii_results): (Vec<_>, Vec<_>) =
        stats.iter().partition(|r| r.tier1 != "No PII");

    let mut total_pii: usize = 0;
    let mut total_no_pii: usize = 0;

    for result in &pii_results {
        total_pii += result.count;
    }
    for result in &no_pii_results {
        total_no_pii += result.count;
    }

    let pii_percentage = if total_columns > 0 {
        (total_pii as f64 / total_columns as f64) * 100.0
    } else {
        0.0
    };
    let no_pii_percentage = if total_columns > 0 {
        (total_no_pii as f64 / total_columns as f64) * 100.0
    } else {
        0.0
    };

    // Calculate risk level
    let risk_level = if total_pii as f64 / total_columns as f64 > 0.25 {
        "CRITICAL"
    } else if total_pii as f64 / total_columns as f64 > 0.1 {
        "HIGH"
    } else {
        "LOW"
    };

    println!("  {:<19} {:>4}", "Tables scanned", unique_tables);
    println!("  {:<19} {:>4}", "Columns scanned", total_columns);
    println!();
    println!(
        "  {:<19} {:>4} ({:.1}%)",
        "PII columns", total_pii, pii_percentage
    );
    println!(
        "  {:<19} {:>4} ({:.1}%)",
        "Non-PII columns", total_no_pii, no_pii_percentage
    );
    println!();

    // Add colored risk level
    let risk_color = match risk_level {
        "CRITICAL" | "HIGH" => "\x1b[31m", // Red
        "LOW" => "\x1b[32m",               // Green
        _ => "",
    };
    let reset = "\x1b[0m";
    println!(
        "  {:<18} {}{}{}",
        "Risk level", risk_color, risk_level, reset
    );
    println!();

    // Detected categories section
    println!("\x1b[1mDetected Categories\x1b[0m");
    println!("{}", "─".repeat(59));

    // Group PII results by tier1 category
    let mut tier1_groups: BTreeMap<&'static str, Vec<&TieredCategoryResult>> = BTreeMap::new();
    for result in &pii_results {
        tier1_groups.entry(result.tier1).or_default().push(result);
    }

    // Collect tier1 categories with their totals, sorted by count descending
    let mut tier1_totals: Vec<(&'static str, usize)> = Vec::new();
    for tier1_cat in TIER1_CATEGORIES_ORDERED {
        if let Some(group) = tier1_groups.get(tier1_cat) {
            let count: usize = group.iter().map(|r| r.count).sum();
            if count > 0 {
                tier1_totals.push((tier1_cat, count));
            }
        }
    }
    // Safety net: surface any PII that mapped to "Other" so it isn't silently dropped.
    // This fires when a new pii_type is added to classify_column but map_to_tier1_category
    // isn't updated. Keeps the breakdown honest instead of hiding columns.
    if let Some(other_group) = tier1_groups.get("Other") {
        let count: usize = other_group.iter().map(|r| r.count).sum();
        if count > 0 {
            tier1_totals.push(("Other", count));
        }
    }
    tier1_totals.sort_by_key(|b| std::cmp::Reverse(b.1)); // Sort descending by count

    // Find the longest category name for alignment
    let max_category_len = TIER1_CATEGORIES_ORDERED
        .iter()
        .map(|s| s.len())
        .max()
        .unwrap_or(20);

    // Print detected categories
    for (tier1, count) in &tier1_totals {
        let pii_percentage = ((*count as f64) / (total_pii as f64)) * 100.0;
        println!(
            "  {:<width$} {:>5}  {:.1}%",
            tier1,
            count,
            pii_percentage,
            width = max_category_len
        );
    }
    println!();

    // Top findings section
    println!("\x1b[1mTop Findings\x1b[0m");
    println!("{}", "─".repeat(59));

    // Show top 3 tier1 categories with examples
    for (idx, (tier1, _)) in tier1_totals.iter().take(3).enumerate() {
        if idx > 0 {
            println!();
        }
        println!("{}", tier1);

        if let Some(group) = tier1_groups.get(tier1) {
            // Collect all examples across tier2 categories
            let mut all_examples: Vec<String> = Vec::new();
            for result in group {
                all_examples.extend(result.examples.clone());
            }

            if verbose {
                // Show all examples in verbose mode
                for example in &all_examples {
                    println!("  {}", example);
                }
            } else {
                // Show up to 3 examples and "... and N more" if needed
                for example in all_examples.iter().take(3) {
                    println!("  {}", example);
                }

                // If more than 3 examples, show "... and N more"
                if all_examples.len() > 3 {
                    let remaining = all_examples.len() - 3;
                    println!("  ... and {} more", remaining);
                }
            }
        }
    }
    println!();

    if !verbose {
        println!("\x1b[1mHint\x1b[0m");
        println!("  Use --verbose to show all detected columns");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::config::Config;

    fn dummy_config() -> Config {
        Config::load().unwrap_or_default()
    }

    // ── parse_columnar_json ────────────────────────────────────────────────

    #[test]
    fn parse_lowercase_headers() {
        let json = r#"{"columns":["table_name","column_name"],"rows":[["users","email"],["users","first_name"]]}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
        assert_eq!(pairs[1], ("users".to_string(), "first_name".to_string()));
    }

    #[test]
    fn parse_uppercase_headers() {
        let json = r#"{"columns":["TABLE_NAME","COLUMN_NAME"],"rows":[["orders","customer_id"]]}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("orders".to_string(), "customer_id".to_string()));
    }

    #[test]
    fn parse_extra_columns_ignored() {
        // Real tkdbr output has a count field and extra columns — only TABLE_NAME/COLUMN_NAME matter
        let json = r#"{"columns":["TABLE_NAME","COLUMN_NAME","DATA_TYPE"],"count":2,"rows":[["users","email","varchar"],["users","id","int"]]}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].1, "email");
        assert_eq!(pairs[1].1, "id");
    }

    #[test]
    fn parse_column_name_not_first_position() {
        // COLUMN_NAME at index 0, TABLE_NAME at index 1
        let json = r#"{"columns":["COLUMN_NAME","TABLE_NAME"],"rows":[["email","users"]]}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn parse_missing_column_name_header_errors() {
        let json = r#"{"columns":["TABLE_NAME"],"rows":[["users"]]}"#;
        assert!(parse_columnar_json(json).is_err());
    }

    #[test]
    fn parse_missing_table_name_header_errors() {
        let json = r#"{"columns":["COLUMN_NAME"],"rows":[["email"]]}"#;
        assert!(parse_columnar_json(json).is_err());
    }

    #[test]
    fn parse_invalid_json_errors() {
        assert!(parse_columnar_json("not json").is_err());
    }

    #[test]
    fn parse_empty_rows() {
        let json = r#"{"columns":["TABLE_NAME","COLUMN_NAME"],"rows":[]}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_real_tkdbr_output() {
        // Exact shape from the conversation example
        let json = r#"{"columns":["TABLE_NAME","COLUMN_NAME"],"count":5,"rows":[["_jarden_account_lookup","account_id"],["_jarden_account_lookup","cp_code"],["_jarden_account_lookup","id"],["_jarden_assets","_legacy_asset_code"],["_jarden_assets","_legacy_business"]]}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 5);
        assert_eq!(pairs[0].1, "account_id");
        assert_eq!(pairs[2].1, "id");
    }

    // ── psql format tests ─────────────────────────────────────────────────────

    #[test]
    fn parse_psql_object_format() {
        // psql object format with lowercase field names
        let json = r#"{"rows":[{"column_name":"id","table_name":"users"},{"column_name":"email","table_name":"users"}],"count":2}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("users".to_string(), "id".to_string()));
        assert_eq!(pairs[1], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn parse_psql_object_mixed_case_fields() {
        // psql with mixed-case field names
        let json = r#"{"rows":[{"Column_Name":"first_name","Table_Name":"users"}],"count":1}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("users".to_string(), "first_name".to_string()));
    }

    #[test]
    fn parse_psql_object_with_extra_fields() {
        // psql with additional fields that should be ignored
        let json = r#"{"rows":[{"table_name":"orders","column_name":"customer_id","data_type":"integer","is_nullable":false}],"count":1}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("orders".to_string(), "customer_id".to_string()));
    }

    #[test]
    fn parse_psql_object_multiple_tables() {
        // psql with multiple tables and columns
        let json = r#"{"rows":[{"column_name":"id","table_name":"users"},{"column_name":"full_name","table_name":"users"},{"column_name":"email","table_name":"users"},{"column_name":"status","table_name":"users"},{"column_name":"created_at","table_name":"users"},{"column_name":"last_login_at","table_name":"users"}],"count":6}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 6);
        assert_eq!(pairs[0], ("users".to_string(), "id".to_string()));
        assert_eq!(pairs[1], ("users".to_string(), "full_name".to_string()));
        assert_eq!(pairs[2], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn parse_psql_object_missing_column_name_field_errors() {
        let json = r#"{"rows":[{"table_name":"users"}],"count":1}"#;
        let result = parse_columnar_json(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no valid"));
    }

    #[test]
    fn parse_psql_object_missing_table_name_field_errors() {
        let json = r#"{"rows":[{"column_name":"email"}],"count":1}"#;
        let result = parse_columnar_json(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no valid"));
    }

    #[test]
    fn parse_psql_object_empty_rows() {
        let json = r#"{"rows":[],"count":0}"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert!(pairs.is_empty());
    }

    // ── aggregate_by_category ─────────────────────────────────────────────

    #[test]
    fn aggregate_classifies_pii_columns() {
        let cfg = dummy_config();
        let pairs = vec![
            ("users".to_string(), "email".to_string()),
            ("users".to_string(), "first_name".to_string()),
            ("users".to_string(), "order_date".to_string()),
        ];
        let stats = aggregate_by_category(&pairs, &cfg);
        // Should have at least one PII and one No PII entry
        assert!(stats.iter().any(|r| r.tier1 != "No PII"));
        assert!(stats.iter().any(|r| r.tier1 == "No PII"));
    }

    #[test]
    fn aggregate_examples_capped_at_three() {
        let cfg = dummy_config();
        let pairs = (1..=5)
            .map(|i| (format!("t{i}"), "first_name".to_string()))
            .collect::<Vec<_>>();
        let stats = aggregate_by_category(&pairs, &cfg);
        // Find the "Names" entry (first_name maps to "Names" tier1 category)
        let names_entry = stats.iter().find(|r| r.tier1 == "Names");
        if let Some(entry) = names_entry {
            assert_eq!(entry.count, 5);
            assert!(entry.examples.len() <= 3);
        }
    }

    #[test]
    fn aggregate_non_pii_columns_go_to_no_pii() {
        let cfg = dummy_config();
        let pairs = vec![
            ("t".to_string(), "order_date".to_string()),
            ("t".to_string(), "legacy_business".to_string()),
        ];
        let stats = aggregate_by_category(&pairs, &cfg);
        let no_pii = stats.iter().find(|r| r.tier1 == "No PII");
        assert!(no_pii.map(|r| r.count).unwrap_or(0) > 0);
    }

    // ── Category mapping tests ───────────────────────────────────────────

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
    }

    #[test]
    fn map_unknown_to_other() {
        assert_eq!(map_to_tier1_category("unknown_type"), "Other");
    }

    // ── psql text table format tests ──────────────────────────────────────────

    #[test]
    fn parse_psql_text_table_basic() {
        let input = " table_name |  column_name\n------------+---------------\n users      | id\n users      | full_name\n users      | email\n users      | status\n users      | created_at\n users      | last_login_at\n(6 rows)\n";
        let pairs = parse_columnar_json(input).unwrap();
        assert_eq!(pairs.len(), 6);
        assert_eq!(pairs[0], ("users".to_string(), "id".to_string()));
        assert_eq!(pairs[1], ("users".to_string(), "full_name".to_string()));
        assert_eq!(pairs[2], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn parse_psql_text_table_exact_user_output() {
        // Exact output from the user's psql session
        let input = " table_name |  column_name\n------------+---------------\n users      | id\n users      | full_name\n users      | email\n users      | status\n users      | created_at\n users      | last_login_at\n(6 rows)\n";
        let pairs = parse_columnar_json(input).unwrap();
        assert_eq!(pairs.len(), 6);
        assert_eq!(pairs[5], ("users".to_string(), "last_login_at".to_string()));
    }

    #[test]
    fn parse_psql_text_table_zero_rows() {
        let input = " table_name |  column_name\n------------+---------------\n(0 rows)\n";
        let pairs = parse_columnar_json(input).unwrap();
        assert!(pairs.is_empty());
    }

    #[test]
    fn parse_psql_text_table_one_row() {
        let input = " table_name | column_name\n------------+-------------\n orders     | customer_id\n(1 row)\n";
        let pairs = parse_columnar_json(input).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("orders".to_string(), "customer_id".to_string()));
    }

    #[test]
    fn parse_psql_text_table_multiple_tables() {
        let input = " table_name | column_name\n------------+-------------\n users      | email\n orders     | customer_id\n payments   | card_number\n(3 rows)\n";
        let pairs = parse_columnar_json(input).unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
        assert_eq!(pairs[1], ("orders".to_string(), "customer_id".to_string()));
        assert_eq!(
            pairs[2],
            ("payments".to_string(), "card_number".to_string())
        );
    }

    #[test]
    fn parse_psql_text_table_missing_table_name_errors() {
        let input = " column_name\n-------------\n email\n(1 row)\n";
        let result = parse_columnar_json(input);
        assert!(result.is_err());
    }

    #[test]
    fn parse_psql_text_table_columns_reversed() {
        // column_name before table_name in header
        let input = " column_name | table_name\n-------------+------------\n email       | users\n(1 row)\n";
        let pairs = parse_columnar_json(input).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    // ── id pii_type mapping (bug fix: was silently dropped into "Other") ──────

    #[test]
    fn map_id_to_online_technical() {
        // classify_column returns "id" for all PERSON_ID_PREFIXES columns;
        // this must map to a visible tier-1 category, not "Other".
        assert_eq!(map_to_tier1_category("id"), "Online & technical");
    }

    #[test]
    fn aggregate_person_id_columns_appear_in_online_technical() {
        let cfg = dummy_config();
        // These columns all hit the PERSON_ID_PREFIXES pass → classify returns "id"
        let pairs = vec![
            ("users".to_string(), "customer_id".to_string()),
            ("events".to_string(), "user_id".to_string()),
            ("sessions".to_string(), "session_id".to_string()),
            ("devices".to_string(), "device_id".to_string()),
        ];
        let stats = aggregate_by_category(&pairs, &cfg);

        let online = stats.iter().find(|r| r.tier1 == "Online & technical");
        assert!(online.is_some(), "expected Online & technical tier-1 entry");
        assert_eq!(online.unwrap().count, 4);

        // None should land in "Other"
        assert!(
            !stats.iter().any(|r| r.tier1 == "Other"),
            "id-typed columns must not fall into Other"
        );
    }

    #[test]
    fn no_pii_type_returned_by_classify_maps_to_other() {
        // Exhaustive check: every pii_type that classify_column can return
        // must have an explicit tier-1 mapping (not fall through to "Other").
        // If this fails, a new type was added to patterns.rs without updating
        // map_to_tier1_category.
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
