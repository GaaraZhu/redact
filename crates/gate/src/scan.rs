use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};

use common::config::Config;
use common::error::exit_with_error;
use common::patterns::{classify_column, map_to_tier1_category};

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
pub fn run(verbose: bool, json: bool, review: bool) {
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
        if json {
            println!("{}", empty_json_report());
        } else {
            println!("No columns found in input.");
        }
        std::process::exit(0);
    }

    // Classify each column and aggregate results
    let stats = aggregate_by_category(&pairs, &config);

    let has_pii = stats.iter().any(|r| r.tier1 != "No PII");

    // Render the report. --review implies verbose so every column is visible
    // before the user is asked about it.
    if json {
        if review {
            eprintln!("error: --review is not supported with --json");
            std::process::exit(1);
        }
        print_json_report(&pairs, &stats);
    } else {
        print_report(&pairs, &stats, verbose || review);
    }

    // --review: interactive false-positive triage
    if review {
        if !has_pii {
            println!("No PII columns detected — nothing to review.");
        } else {
            run_review();
        }
    }

    // Exit code: 0 if no PII found, 1 if any PII columns detected
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
    // Try JSON first
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input.trim()) {
        // Databricks API response: {"manifest": {"schema": {"columns": [...]}}, "result": {"data_array": [...]}}
        if value.get("manifest").is_some() && value.get("result").is_some() {
            return parse_databricks_api_response(&value);
        }

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

    // Fall back to CSV (DBeaver, DataGrip, TablePlus, etc.)
    let stripped = input.strip_prefix('\u{FEFF}').unwrap_or(input);
    if stripped.lines().any(|l| l.contains(',')) {
        return parse_csv(stripped);
    }

    Err(
        "input is not valid JSON, psql table format, or CSV — pipe the output of a schema query into gate scan."
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

/// Parse CSV export from GUI clients (DBeaver, DataGrip, TablePlus, etc.).
/// Handles RFC 4180 quoting, UTF-8 BOM, and CRLF line endings.
/// Expects a header row with `table_name` and `column_name` columns (case-insensitive).
fn parse_csv(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut lines = text.lines();

    let header_line = loop {
        match lines.next() {
            Some(line) if !line.trim().is_empty() => break line,
            Some(_) => continue,
            None => return Err("empty CSV input".to_string()),
        }
    };

    let headers: Vec<String> = split_csv_row(header_line)
        .into_iter()
        .map(|h| h.trim().to_lowercase())
        .collect();

    let table_idx = headers
        .iter()
        .position(|h| h == "table_name")
        .ok_or_else(|| {
            "table_name column not found in CSV — query must SELECT table_name, column_name."
                .to_string()
        })?;
    let column_idx = headers
        .iter()
        .position(|h| h == "column_name")
        .ok_or_else(|| {
            "column_name column not found in CSV — query must SELECT table_name, column_name."
                .to_string()
        })?;

    let mut pairs = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cells = split_csv_row(line);
        let table = cells
            .get(table_idx)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let col = cells
            .get(column_idx)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if !table.is_empty() && !col.is_empty() {
            pairs.push((table, col));
        }
    }

    Ok(pairs)
}

/// Split one CSV row into fields following RFC 4180: commas delimit fields,
/// double-quotes wrap fields that contain commas/quotes/newlines, and `""` inside
/// a quoted field represents a literal quote character.
fn split_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                fields.push(field.clone());
                field.clear();
            }
            _ => field.push(ch),
        }
    }
    fields.push(field);
    fields
}

/// Parse array-of-arrays format: `{"columns": [...], "rows": [[...], ...]}`
/// Parse Databricks API response:
/// `{"manifest": {"schema": {"columns": [{"name": "TABLE_NAME", ...}, ...]}}, "result": {"data_array": [[...], ...]}}`
fn parse_databricks_api_response(
    value: &serde_json::Value,
) -> Result<Vec<(String, String)>, String> {
    let columns = value
        .get("manifest")
        .and_then(|m| m.get("schema"))
        .and_then(|s| s.get("columns"))
        .and_then(|c| c.as_array())
        .ok_or("Databricks response missing manifest.schema.columns")?;

    let mut table_idx = None;
    let mut column_idx = None;
    for col in columns {
        if let Some(name) = col.get("name").and_then(|n| n.as_str()) {
            match name.to_lowercase().as_str() {
                "table_name" => {
                    table_idx = col
                        .get("position")
                        .and_then(|p| p.as_u64())
                        .map(|p| p as usize)
                }
                "column_name" => {
                    column_idx = col
                        .get("position")
                        .and_then(|p| p.as_u64())
                        .map(|p| p as usize)
                }
                _ => {}
            }
        }
    }

    let table_idx = table_idx.ok_or(
        "Databricks response missing TABLE_NAME column — query must SELECT TABLE_NAME, COLUMN_NAME",
    )?;
    let column_idx = column_idx.ok_or(
        "Databricks response missing COLUMN_NAME column — query must SELECT TABLE_NAME, COLUMN_NAME"
    )?;

    let data_array = value
        .get("result")
        .and_then(|r| r.get("data_array"))
        .and_then(|d| d.as_array())
        .ok_or("Databricks response missing result.data_array")?;

    let mut pairs = Vec::new();
    for row in data_array {
        if let Some(row_arr) = row.as_array() {
            if let (Some(table), Some(col)) = (row_arr.get(table_idx), row_arr.get(column_idx)) {
                if let (Some(t), Some(c)) = (table.as_str(), col.as_str()) {
                    pairs.push((t.to_string(), c.to_string()));
                }
            }
        }
    }

    Ok(pairs)
}

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
        entry.examples.push(format!("{}.{}", table, col));
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

/// Sensitivity weight for a tier-1 reporting category.
///
/// 3 = Critical  — identity theft enablers; regulated (HIPAA / PCI / GDPR special category)
/// 2 = Elevated  — direct PII; breach-reportable; linkage risk
/// 1 = Standard  — PII but less sensitive; often contextual
/// 0 = not a PII category
fn category_weight(tier1: &str) -> u8 {
    match tier1 {
        "Government IDs" | "Health & medical" | "Financial" | "Biometric" => 3,
        "Contact"
        | "Names"
        | "Date of birth"
        | "Location of birth"
        | "Family & relationships"
        | "Employment" => 2,
        "Address & location" | "Online & technical" | "Demographics" => 1,
        _ => 0,
    }
}

/// Compute risk level from weighted category presence.
///
/// max_tier  = highest weight tier with ≥1 column present
/// high_count = columns in tier-3 (Critical) categories
/// pii_ratio  = total_pii / total_columns
///
/// CRITICAL: max_tier==3 AND (high_count >= 3 OR pii_ratio > 0.10)
///           max_tier==2 AND pii_ratio > 0.25
/// HIGH:     max_tier==3 (any critical-sensitivity column present)
///           max_tier==2 AND pii_ratio > 0.05
///           max_tier==1 AND pii_ratio > 0.25
/// LOW:      everything else with some PII present
/// NONE:     no PII columns detected
fn compute_risk_level(pii_results: &[&TieredCategoryResult], total_columns: usize) -> &'static str {
    if total_columns == 0 || pii_results.is_empty() {
        return "NONE";
    }

    let total_pii: usize = pii_results.iter().map(|r| r.count).sum();
    let pii_ratio = total_pii as f64 / total_columns as f64;

    let max_tier = pii_results
        .iter()
        .map(|r| category_weight(r.tier1))
        .max()
        .unwrap_or(0);

    let high_count: usize = pii_results
        .iter()
        .filter(|r| category_weight(r.tier1) == 3)
        .map(|r| r.count)
        .sum();

    match max_tier {
        3 => {
            if high_count >= 3 || pii_ratio > 0.10 {
                "CRITICAL"
            } else {
                "HIGH"
            }
        }
        2 => {
            if pii_ratio > 0.25 {
                "CRITICAL"
            } else if pii_ratio > 0.05 {
                "HIGH"
            } else {
                "LOW"
            }
        }
        1 if pii_ratio > 0.25 => "HIGH",
        _ => "LOW",
    }
}

fn sensitivity_label(weight: u8) -> &'static str {
    match weight {
        3 => "critical",
        2 => "elevated",
        1 => "standard",
        _ => "unknown",
    }
}

fn empty_json_report() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "risk_level": "NONE",
        "tables_scanned": 0,
        "columns_scanned": 0,
        "pii_columns": 0,
        "non_pii_columns": 0,
        "pii_percentage": 0.0,
        "categories": []
    }))
    .unwrap()
}

/// Emit the scan results as pretty-printed JSON.
fn print_json_report(pairs: &[(String, String)], stats: &[TieredCategoryResult]) {
    let total_columns = pairs.len();
    let unique_tables = pairs
        .iter()
        .map(|(t, _)| t)
        .collect::<std::collections::HashSet<_>>()
        .len();

    let (pii_results, no_pii_results): (Vec<_>, Vec<_>) =
        stats.iter().partition(|r| r.tier1 != "No PII");

    let total_pii: usize = pii_results.iter().map(|r| r.count).sum();
    let total_no_pii: usize = no_pii_results.iter().map(|r| r.count).sum();
    let pii_percentage = if total_columns > 0 {
        (total_pii as f64 / total_columns as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let risk_level = compute_risk_level(&pii_results, total_columns);

    // Group examples by tier-1 category, preserving TIER1_CATEGORIES_ORDERED order
    let mut tier1_examples: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for result in &pii_results {
        tier1_examples
            .entry(result.tier1)
            .or_default()
            .extend(result.examples.iter().map(String::as_str));
    }

    let mut categories = Vec::new();
    for cat in TIER1_CATEGORIES_ORDERED {
        if let Some(columns) = tier1_examples.get(cat) {
            let count = columns.len();
            categories.push(serde_json::json!({
                "name": cat,
                "sensitivity": sensitivity_label(category_weight(cat)),
                "count": count,
                "columns": columns,
            }));
        }
    }
    // Safety-net "Other" bucket
    if let Some(columns) = tier1_examples.get("Other") {
        categories.push(serde_json::json!({
            "name": "Other",
            "sensitivity": "unknown",
            "count": columns.len(),
            "columns": columns,
        }));
    }

    let output = serde_json::json!({
        "risk_level": risk_level,
        "tables_scanned": unique_tables,
        "columns_scanned": total_columns,
        "pii_columns": total_pii,
        "non_pii_columns": total_no_pii,
        "pii_percentage": pii_percentage,
        "categories": categories,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

/// Print the scan report to stdout.
fn print_report(pairs: &[(String, String)], stats: &[TieredCategoryResult], verbose: bool) {
    let total_columns = pairs.len();
    let unique_tables = pairs
        .iter()
        .map(|(t, _)| t)
        .collect::<std::collections::HashSet<_>>()
        .len();

    let pii_results: Vec<_> = stats.iter().filter(|r| r.tier1 != "No PII").collect();

    let total_pii: usize = pii_results.iter().map(|r| r.count).sum();
    let pii_pct = if total_columns > 0 {
        (total_pii as f64 / total_columns as f64) * 100.0
    } else {
        0.0
    };

    let risk_level = compute_risk_level(&pii_results, total_columns);
    let risk_color = match risk_level {
        "CRITICAL" => "\x1b[31m",
        "HIGH" => "\x1b[33m",
        "LOW" | "NONE" => "\x1b[38;5;40m", // 256-colour green, not theme-remappable
        _ => "",
    };
    let reset = "\x1b[0m";
    let hdr = "\x1b[1;96m"; // bold bright-cyan for section headers

    // ── Header ────────────────────────────────────────────────────────────────
    println!("{hdr}Gate PII Scan{reset}");
    println!("{}", "═".repeat(66));
    println!();

    // ── Summary ───────────────────────────────────────────────────────────────
    println!("  {:<19} {:>4}", "Tables scanned", unique_tables);
    println!("  {:<19} {:>4}", "Columns scanned", total_columns);
    println!();

    let bar_width = 24usize;
    let filled = ((pii_pct / 100.0) * bar_width as f64).round() as usize;
    let filled = filled.min(bar_width);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(bar_width - filled));
    println!(
        "  PII exposure:  {}  {:.1}%  Risk: {}{}{}",
        bar, pii_pct, risk_color, risk_level, reset
    );
    println!();

    // ── Detected Categories table ─────────────────────────────────────────────
    let cat_w = 24usize;
    let sep = "─".repeat(66);

    // Group PII results by tier1 category
    let mut tier1_groups: BTreeMap<&'static str, Vec<&TieredCategoryResult>> = BTreeMap::new();
    for result in &pii_results {
        tier1_groups.entry(result.tier1).or_default().push(result);
    }

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
    tier1_totals.sort_by_key(|b| std::cmp::Reverse(b.1));

    if total_pii > 0 {
        println!("{hdr}Detected Categories{reset}");
        println!("{}", sep);
        println!(
            "  {:<cat_w$}     {:<7}     {:<6}     Sensitivity",
            "Category", "Columns", "Share"
        );
        println!("{}", sep);
        for (tier1, count) in &tier1_totals {
            let share = (*count as f64 / total_pii as f64) * 100.0;
            let sens = sensitivity_label(category_weight(tier1));
            let share_str = format!("{:.1}%", share);
            println!(
                "  {:<cat_w$}     {:<7}     {:<6}     {}",
                tier1, count, share_str, sens
            );
        }
        println!("{}", sep);
        println!();

        // ── Top / All Findings ────────────────────────────────────────────────
        let section_title = if verbose {
            "All Findings"
        } else {
            "Top Findings"
        };
        println!("{hdr}{section_title}{reset}");
        println!("{}", sep);

        let findings_iter: Box<dyn Iterator<Item = _>> = if verbose {
            Box::new(tier1_totals.iter())
        } else {
            Box::new(tier1_totals.iter().take(3))
        };
        for (idx, (tier1, count)) in findings_iter.enumerate() {
            if idx > 0 {
                println!();
            }
            println!("  {:<cat_w$}     {:>7} column(s)", tier1, count);

            if let Some(group) = tier1_groups.get(tier1) {
                let all_examples: Vec<String> = group
                    .iter()
                    .flat_map(|r| r.examples.iter().cloned())
                    .collect();

                if verbose {
                    for example in &all_examples {
                        println!("    {}", example);
                    }
                } else {
                    let preview: Vec<&str> =
                        all_examples.iter().take(3).map(String::as_str).collect();
                    println!("    {}", preview.join(", "));
                    if all_examples.len() > 3 {
                        println!("    ... and {} more", all_examples.len() - 3);
                    }
                }
            }
        }
        println!("{}", sep);
        println!();
    }

    // ── Footer ────────────────────────────────────────────────────────────────
    println!("{hdr}Note{reset}");
    println!("  Scan detects PII by column name only. Gate 2 also");
    println!("  catches values in text/JSON columns at query time.");
    if !verbose {
        println!();
        println!("{hdr}Hint{reset}");
        println!("  Use --verbose to show all detected columns");
        println!("  Use --review to interactively mark false positives");
    }
}

/// Interactive false-positive triage: two single-line prompts — one to add, one to remove.
fn run_review() {
    // Open the console input device directly so prompts work even when stdin is a pipe
    // (e.g. `psql ... | gate scan --review`). Falls back gracefully if no TTY is available.
    // Unix: /dev/tty  Windows: CONIN$ (both bypass stdin redirection)
    let tty_path = if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
    let tty = match std::fs::OpenOptions::new().read(true).open(tty_path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("note: --review requires an interactive terminal");
            return;
        }
    };
    let mut tty_reader = BufReader::new(tty);

    // Load config path and current allowlist up front.
    let path = match common::config::config_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot resolve config path: {e}");
            return;
        }
    };
    // Pre-check write permission before starting the review so the user isn't
    // surprised by an EPERM after completing a long interactive session.
    #[cfg(unix)]
    if path.exists() {
        if let Err(e) = std::fs::OpenOptions::new().write(true).open(&path) {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                common::error::exit_with_error("Config is protected. Run: sudo gate scan --review");
            }
        }
    }
    let content = if path.exists() {
        std::fs::read_to_string(&path).unwrap_or_default()
    } else {
        String::new()
    };
    let existing = crate::allowlist::parse_current_allowlist(&content);

    println!();
    println!("\x1b[1;96mAllowlist false positives\x1b[0m");
    println!("{}", "─".repeat(59));

    // Prompt 1: add to allowlist
    print!("Columns to allowlist (space/comma-separated), or Enter to skip: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if tty_reader.read_line(&mut line).is_err() {
        return;
    }
    let to_add: Vec<String> = parse_name_list(&line)
        .into_iter()
        .filter(|c| !existing.iter().any(|e| e == c))
        .collect();

    // Prompt 2: remove from allowlist (only shown if allowlist is non-empty)
    let mut to_remove: Vec<String> = Vec::new();
    if !existing.is_empty() {
        println!("Currently allowlisted: {}", existing.join(", "));
        print!("Columns to remove (space/comma-separated), or Enter to keep all: ");
        let _ = std::io::stdout().flush();
        let mut line2 = String::new();
        if tty_reader.read_line(&mut line2).is_ok() {
            to_remove = parse_name_list(&line2)
                .into_iter()
                .filter(|c| existing.iter().any(|e| e == c))
                .collect();
        }
    }

    if to_add.is_empty() && to_remove.is_empty() {
        println!("No changes to allowlist.");
        return;
    }

    // Apply adds then removes atomically in a single write.
    let mut new_content = crate::allowlist::add_to_allowlist_in_yaml(&content, &to_add);
    new_content = crate::allowlist::remove_from_allowlist_in_yaml(&new_content, &to_remove);

    if let Err(e) = crate::allowlist::write_atomic(&path, &new_content) {
        if e.downcast_ref::<std::io::Error>()
            .map(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
            .unwrap_or(false)
        {
            common::error::exit_with_error("Config is protected. Run: sudo gate scan --review");
        }
        common::error::exit_with_error(&format!("failed to write config: {e}"));
    }

    println!();
    if !to_add.is_empty() {
        println!("Added {} column(s): {}", to_add.len(), to_add.join(", "));
    }
    if !to_remove.is_empty() {
        println!(
            "Removed {} column(s): {}",
            to_remove.len(),
            to_remove.join(", ")
        );
    }
    println!("Config updated: {}", path.display());
}

/// Split a user input line on spaces and/or commas, returning lowercased column names.
/// Strips a leading `table.` prefix so pasting `users.first_name` works like `first_name`.
fn parse_name_list(input: &str) -> Vec<String> {
    input
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let col = s.rsplit_once('.').map(|(_, c)| c).unwrap_or(s);
            col.to_lowercase()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::config::Config;

    fn dummy_config() -> Config {
        Config::load().unwrap_or_default()
    }

    // ── parse_columnar_json ────────────────────────────────────────────────

    // ── Databricks API response format ────────────────────────────────────────

    #[test]
    fn parse_databricks_api_response_basic() {
        let json = r#"{
            "manifest": {
                "schema": {
                    "columns": [
                        {"name": "TABLE_NAME", "position": 0, "type_name": "STRING"},
                        {"name": "COLUMN_NAME", "position": 1, "type_name": "STRING"}
                    ]
                }
            },
            "result": {
                "data_array": [
                    ["users", "email"],
                    ["users", "first_name"],
                    ["orders", "customer_id"]
                ]
            },
            "status": {"state": "SUCCEEDED"}
        }"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
        assert_eq!(pairs[1], ("users".to_string(), "first_name".to_string()));
        assert_eq!(pairs[2], ("orders".to_string(), "customer_id".to_string()));
    }

    #[test]
    fn parse_databricks_api_response_columns_reversed() {
        // COLUMN_NAME before TABLE_NAME — position field drives the mapping
        let json = r#"{
            "manifest": {
                "schema": {
                    "columns": [
                        {"name": "COLUMN_NAME", "position": 0, "type_name": "STRING"},
                        {"name": "TABLE_NAME", "position": 1, "type_name": "STRING"}
                    ]
                }
            },
            "result": {
                "data_array": [["email", "users"]]
            },
            "status": {"state": "SUCCEEDED"}
        }"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn parse_databricks_api_response_extra_columns_ignored() {
        let json = r#"{
            "manifest": {
                "schema": {
                    "columns": [
                        {"name": "TABLE_NAME", "position": 0, "type_name": "STRING"},
                        {"name": "COLUMN_NAME", "position": 1, "type_name": "STRING"},
                        {"name": "DATA_TYPE", "position": 2, "type_name": "STRING"}
                    ]
                }
            },
            "result": {
                "data_array": [["users", "email", "VARCHAR"]]
            },
            "status": {"state": "SUCCEEDED"}
        }"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn parse_databricks_api_response_missing_column_name_errors() {
        let json = r#"{
            "manifest": {"schema": {"columns": [{"name": "TABLE_NAME", "position": 0}]}},
            "result": {"data_array": [["users"]]}
        }"#;
        assert!(parse_columnar_json(json).is_err());
    }

    #[test]
    fn parse_databricks_api_response_empty_data_array() {
        let json = r#"{
            "manifest": {
                "schema": {
                    "columns": [
                        {"name": "TABLE_NAME", "position": 0},
                        {"name": "COLUMN_NAME", "position": 1}
                    ]
                }
            },
            "result": {"data_array": []}
        }"#;
        let pairs = parse_columnar_json(json).unwrap();
        assert!(pairs.is_empty());
    }

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
    fn aggregate_examples_stores_all() {
        // The cap of 3 lives in display only; aggregation stores every example
        // so JSON output and verbose mode can show the full list.
        let cfg = dummy_config();
        let pairs = (1..=5)
            .map(|i| (format!("t{i}"), "first_name".to_string()))
            .collect::<Vec<_>>();
        let stats = aggregate_by_category(&pairs, &cfg);
        let names_entry = stats.iter().find(|r| r.tier1 == "Names");
        if let Some(entry) = names_entry {
            assert_eq!(entry.count, 5);
            assert_eq!(entry.examples.len(), 5);
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

    // ── compute_risk_level ────────────────────────────────────────────────────

    fn make_result(tier1: &'static str, count: usize) -> TieredCategoryResult {
        TieredCategoryResult {
            tier1,
            count,
            examples: vec![],
        }
    }

    #[test]
    fn risk_single_ssn_is_high_not_low() {
        // 1 SSN column out of 200 — old formula: LOW (0.5%); new: HIGH (any tier-3)
        let r = make_result("Government IDs", 1);
        assert_eq!(compute_risk_level(&[&r], 200), "HIGH");
    }

    #[test]
    fn risk_many_critical_columns_is_critical() {
        // 5 SSN + 3 medical out of 50 — tier-3, high_count >= 3
        let r1 = make_result("Government IDs", 5);
        let r2 = make_result("Health & medical", 3);
        assert_eq!(compute_risk_level(&[&r1, &r2], 50), "CRITICAL");
    }

    #[test]
    fn risk_critical_tier_high_ratio_is_critical() {
        // 12 SSN columns out of 100 — tier-3, pii_ratio > 0.10
        let r = make_result("Government IDs", 12);
        assert_eq!(compute_risk_level(&[&r], 100), "CRITICAL");
    }

    #[test]
    fn risk_many_names_and_emails_is_critical() {
        // 30 name+email out of 100 — tier-2, pii_ratio > 0.25
        let r1 = make_result("Names", 20);
        let r2 = make_result("Contact", 10);
        assert_eq!(compute_risk_level(&[&r1, &r2], 100), "CRITICAL");
    }

    #[test]
    fn risk_few_emails_is_high() {
        // 6 email+phone out of 100 — tier-2, pii_ratio > 0.05
        let r = make_result("Contact", 6);
        assert_eq!(compute_risk_level(&[&r], 100), "HIGH");
    }

    #[test]
    fn risk_tiny_contact_exposure_is_low() {
        // 5 email columns out of 100 — tier-2, pii_ratio == 0.05, not > 0.05
        let r = make_result("Contact", 5);
        assert_eq!(compute_risk_level(&[&r], 100), "LOW");
    }

    #[test]
    fn risk_address_only_under_threshold_is_low() {
        // 20 address columns out of 100 — tier-1, pii_ratio = 0.20
        let r = make_result("Address & location", 20);
        assert_eq!(compute_risk_level(&[&r], 100), "LOW");
    }

    #[test]
    fn risk_many_address_columns_is_high() {
        // 30 address cols out of 100 — tier-1, pii_ratio > 0.25
        let r = make_result("Address & location", 30);
        assert_eq!(compute_risk_level(&[&r], 100), "HIGH");
    }

    #[test]
    fn risk_no_pii_is_none() {
        assert_eq!(compute_risk_level(&[], 100), "NONE");
        assert_eq!(compute_risk_level(&[], 0), "NONE");
    }

    #[test]
    fn risk_demographics_only_is_low() {
        // Demographics is tier-1; even if > 0.25 it's HIGH, but low count is LOW
        let r = make_result("Demographics", 5);
        assert_eq!(compute_risk_level(&[&r], 100), "LOW");
    }

    // ── print_json_report ─────────────────────────────────────────────────────

    fn run_json_report(pairs: &[(&str, &str)]) -> serde_json::Value {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(t, c)| (t.to_string(), c.to_string()))
            .collect();
        let cfg = dummy_config();
        let stats = aggregate_by_category(&owned, &cfg);
        // Capture stdout by building the JSON value directly (same logic as print_json_report)
        let (pii_results, no_pii_results): (Vec<_>, Vec<_>) =
            stats.iter().partition(|r| r.tier1 != "No PII");
        let total_columns = owned.len();
        let total_pii: usize = pii_results.iter().map(|r| r.count).sum();
        let total_no_pii: usize = no_pii_results.iter().map(|r| r.count).sum();
        let pii_percentage = if total_columns > 0 {
            (total_pii as f64 / total_columns as f64 * 1000.0).round() / 10.0
        } else {
            0.0
        };
        let risk_level = compute_risk_level(&pii_results, total_columns);
        let mut tier1_examples: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for result in &pii_results {
            tier1_examples
                .entry(result.tier1)
                .or_default()
                .extend(result.examples.iter().map(String::as_str));
        }
        let mut categories = Vec::new();
        for cat in TIER1_CATEGORIES_ORDERED {
            if let Some(columns) = tier1_examples.get(cat) {
                categories.push(serde_json::json!({
                    "name": cat,
                    "sensitivity": sensitivity_label(category_weight(cat)),
                    "count": columns.len(),
                    "columns": columns,
                }));
            }
        }
        serde_json::json!({
            "risk_level": risk_level,
            "tables_scanned": owned.iter().map(|(t,_)| t.as_str()).collect::<std::collections::HashSet<_>>().len(),
            "columns_scanned": total_columns,
            "pii_columns": total_pii,
            "non_pii_columns": total_no_pii,
            "pii_percentage": pii_percentage,
            "categories": categories,
        })
    }

    #[test]
    fn json_report_shape_and_top_level_fields() {
        let v = run_json_report(&[
            ("users", "email"),
            ("users", "first_name"),
            ("users", "status"),
        ]);
        assert_eq!(v["tables_scanned"], 1);
        assert_eq!(v["columns_scanned"], 3);
        assert_eq!(v["pii_columns"], 2);
        assert_eq!(v["non_pii_columns"], 1);
        assert!(v["risk_level"].is_string());
        assert!(v["categories"].is_array());
    }

    #[test]
    fn json_report_categories_include_all_columns_not_capped() {
        // 5 different tables, same PII column — all 5 should appear in JSON
        let _pairs: Vec<(&str, &str)> = (0..5)
            .map(|i| {
                if i == 0 {
                    ("t0", "email")
                } else {
                    ("t1", "email")
                }
            })
            .collect();
        let pairs = [
            ("t0", "email"),
            ("t1", "email"),
            ("t2", "email"),
            ("t3", "email"),
            ("t4", "email"),
        ];
        let v = run_json_report(&pairs);
        let cats = v["categories"].as_array().unwrap();
        let contact = cats.iter().find(|c| c["name"] == "Contact").unwrap();
        assert_eq!(contact["count"], 5);
        assert_eq!(contact["columns"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn json_report_sensitivity_labels_are_correct() {
        let v = run_json_report(&[("t", "ssn"), ("t", "email"), ("t", "street")]);
        let cats = v["categories"].as_array().unwrap();
        let gov = cats.iter().find(|c| c["name"] == "Government IDs");
        let contact = cats.iter().find(|c| c["name"] == "Contact");
        let addr = cats.iter().find(|c| c["name"] == "Address & location");
        assert_eq!(gov.unwrap()["sensitivity"], "critical");
        assert_eq!(contact.unwrap()["sensitivity"], "elevated");
        assert_eq!(addr.unwrap()["sensitivity"], "standard");
    }

    #[test]
    fn json_report_empty_input_is_valid() {
        let v: serde_json::Value = serde_json::from_str(&empty_json_report()).unwrap();
        assert_eq!(v["risk_level"], "NONE");
        assert_eq!(v["columns_scanned"], 0);
        assert_eq!(v["categories"].as_array().unwrap().len(), 0);
    }

    // ── CSV parsing ───────────────────────────────────────────────────────────

    #[test]
    fn csv_basic() {
        let csv = "table_name,column_name\nusers,email\nusers,first_name\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("users".to_string(), "email".to_string()),
                ("users".to_string(), "first_name".to_string()),
            ]
        );
    }

    #[test]
    fn csv_quoted_fields() {
        let csv = "\"table_name\",\"column_name\"\n\"users\",\"email\"\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn csv_quoted_field_with_embedded_comma() {
        // table name containing a comma, wrapped in quotes
        let csv = "table_name,column_name\n\"orders,archive\",customer_id\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(
            pairs[0],
            ("orders,archive".to_string(), "customer_id".to_string())
        );
    }

    #[test]
    fn csv_quoted_field_with_escaped_quote() {
        let csv = "table_name,column_name\n\"user\"\"s\",email\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(pairs[0], ("user\"s".to_string(), "email".to_string()));
    }

    #[test]
    fn csv_uppercase_headers() {
        let csv = "TABLE_NAME,COLUMN_NAME\norders,total\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(pairs[0], ("orders".to_string(), "total".to_string()));
    }

    #[test]
    fn csv_extra_columns_ignored() {
        let csv = "table_schema,table_name,column_name,data_type\npublic,users,email,text\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn csv_columns_in_any_order() {
        let csv = "column_name,table_name\nemail,users\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn csv_utf8_bom_stripped() {
        let csv = "\u{FEFF}table_name,column_name\nusers,email\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn csv_crlf_line_endings() {
        let csv = "table_name,column_name\r\nusers,email\r\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(pairs[0], ("users".to_string(), "email".to_string()));
    }

    #[test]
    fn csv_skips_blank_lines() {
        let csv = "table_name,column_name\nusers,email\n\norders,total\n";
        let pairs = parse_columnar_json(csv).unwrap();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn csv_missing_table_name_column_errors() {
        let csv = "column_name,data_type\nemail,text\n";
        assert!(parse_columnar_json(csv).is_err());
    }
}
