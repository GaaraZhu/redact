/// Latency regression test for Gate 2 redaction.
///
/// Builds a realistic columnar payload — the format database tools emit —
/// with a mix of:
///   - PII columns caught by name (fast path, no regex needed)
///   - Safe columns with short values
///   - Ambiguous columns with longer strings that must be regex-scanned
///   - A few JSONB-shaped strings (starts with `{`) to stress the JSONB guard
///
/// Runs N iterations and asserts the average is under 10 ms.
/// Run with `cargo test -p common --test latency -- --nocapture` to see timing.
use common::{
    config::PiiConfig,
    redactor::{redact_with_stats, RedactPlan},
};
use serde_json::{json, Value};
use std::time::Instant;

const ROWS: usize = 500;
const ITERATIONS: usize = 30;

// Release builds are ~10x faster than debug builds.
// Run with `cargo test -p common --test latency --release -- --nocapture`
// to get numbers that match production behaviour.
// Baseline (unoptimised): ~7ms. Optimised target: < 6.5ms.
#[cfg(not(debug_assertions))]
const TARGET_MS: f64 = 6.5;

#[cfg(debug_assertions)]
const TARGET_MS: f64 = 100.0;

fn build_payload() -> Value {
    // PII columns — caught by column-name rules, no regex needed.
    let pii_cols = ["email", "first_name", "ssn", "phone", "address"];
    // Safe columns with short, obviously non-PII values.
    let safe_cols = ["id", "status", "region", "currency", "channel"];
    // Ambiguous columns: generic names + longer strings that must reach the regex scanner.
    let ambiguous_cols = ["note", "description", "comment", "tags", "metadata"];

    let ambiguous_values = [
        "Customer requested expedited shipping for their order placed last Tuesday.",
        "Product returned due to manufacturing defect; refund issued to original payment method.",
        "Account flagged for review after multiple failed login attempts from new device.",
        "Subscription renewed automatically; invoice sent to billing contact on file.",
        "Delivery attempted twice; package held at local facility awaiting pickup.",
    ];

    // A few values that start with `{` to exercise the JSONB guard path.
    let jsonb_like = [
        r#"{"key": "some value", "count": 42}"#,
        r#"{"tags": ["a", "b", "c"]}"#,
        r#"{"nested": {"x": 1}}"#,
    ];

    let mut columns: Vec<&str> = Vec::new();
    columns.extend_from_slice(&pii_cols);
    columns.extend_from_slice(&safe_cols);
    columns.extend_from_slice(&ambiguous_cols);

    let rows: Vec<Value> = (0..ROWS)
        .map(|i| {
            let mut cells: Vec<Value> = Vec::new();
            // PII column values — caught by name, skips regex.
            cells.push(json!(format!("user{}@example.com", i)));
            cells.push(json!(format!("User{}", i)));
            cells.push(json!("123-45-6789"));
            cells.push(json!("555-867-5309"));
            cells.push(json!(format!("{} Main St, Springfield", i)));
            // Safe column values.
            cells.push(json!(i.to_string()));
            cells.push(json!("active"));
            cells.push(json!("US"));
            cells.push(json!("USD"));
            cells.push(json!("online"));
            // Ambiguous columns — must be scanned by regex.
            for j in 0..ambiguous_cols.len() {
                if j == ambiguous_cols.len() - 1 && i % 10 == 0 {
                    // Every 10th row: inject a JSONB-shaped string.
                    cells.push(json!(jsonb_like[i / 10 % jsonb_like.len()]));
                } else {
                    cells.push(json!(ambiguous_values[(i + j) % ambiguous_values.len()]));
                }
            }
            Value::Array(cells)
        })
        .collect();

    json!({
        "columns": columns,
        "rows": rows,
    })
}

#[test]
fn gate2_average_latency_under_10ms() {
    let payload = build_payload();
    let plan = RedactPlan::empty();
    let config = PiiConfig::default();

    // Warm up — first call compiles patterns; we measure steady state.
    let _ = redact_with_stats(payload.clone(), &plan, &config);

    let mut total = std::time::Duration::ZERO;
    for _ in 0..ITERATIONS {
        let p = payload.clone();
        let start = Instant::now();
        let _ = redact_with_stats(p, &plan, &config);
        total += start.elapsed();
    }

    let avg_ms = total.as_secs_f64() * 1000.0 / ITERATIONS as f64;
    println!("\ngate2 average latency: {avg_ms:.2}ms  ({ROWS} rows, {ITERATIONS} iterations)");
    assert!(
        avg_ms < TARGET_MS,
        "average latency {avg_ms:.2}ms exceeds {TARGET_MS}ms target"
    );
}
