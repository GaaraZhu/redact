/// End-to-end latency regression test covering the full gate overhead:
/// Gate 1 (SQL parse → redact plan) + Gate 2 (JSON payload redaction).
///
/// This matches what `overhead_us` records in the stats log:
///   gate1_us + redact_us
///
/// Run with `cargo test -p gate --test latency --release -- --nocapture`
/// to get numbers that match production behaviour.
use common::{
    config::{Action, PiiConfig, WildcardPolicy},
    redactor::{redact_with_stats, RedactPlan},
};
use gate1::{build_plan, extract_columns};
use serde_json::{json, Value};
use std::time::Instant;

const ROWS: usize = 500;
const ITERATIONS: usize = 30;

// Gate 1 is a fixed cost per query; Gate 2 scales with result size.
// Baseline (unoptimised): gate1 ~0.1ms + gate2 ~7ms ≈ 7ms total.
// Optimised target: < 10ms combined.
#[cfg(not(debug_assertions))]
const TARGET_MS: f64 = 10.0;

#[cfg(debug_assertions)]
const TARGET_MS: f64 = 150.0;

/// A realistic SELECT with PII and non-PII columns, JOINs, and a WHERE clause.
const SQL: &str = "
    SELECT
        u.id,
        u.email,
        u.first_name,
        u.last_name,
        u.phone,
        u.address,
        u.ssn,
        u.status,
        u.created_at,
        o.order_id,
        o.total,
        o.currency,
        o.notes
    FROM users u
    JOIN orders o ON o.user_id = u.id
    WHERE u.status = 'active'
      AND o.created_at > '2024-01-01'
    ORDER BY o.created_at DESC
    LIMIT 1000
";

fn build_payload() -> Value {
    let columns = [
        "id",
        "email",
        "first_name",
        "last_name",
        "phone",
        "address",
        "ssn",
        "status",
        "created_at",
        "order_id",
        "total",
        "currency",
        "notes",
    ];

    let ambiguous_values = [
        "Customer requested expedited shipping for their order placed last Tuesday.",
        "Product returned due to manufacturing defect; refund issued to original payment method.",
        "Account flagged for review after multiple failed login attempts from new device.",
        "Subscription renewed automatically; invoice sent to billing contact on file.",
        "Delivery attempted twice; package held at local facility awaiting pickup.",
    ];

    let rows: Vec<Value> = (0..ROWS)
        .map(|i| {
            Value::Array(vec![
                json!(i),                                            // id (number, skipped)
                json!(format!("user{}@example.com", i)),             // email — PII by name
                json!(format!("First{}", i)),                        // first_name — PII by name
                json!(format!("Last{}", i)),                         // last_name — PII by name
                json!("555-867-5309"),                               // phone — PII by name
                json!(format!("{} Main St", i)),                     // address — PII by name
                json!("123-45-6789"),                                // ssn — PII by name
                json!("active"),                                     // status — safe
                json!("2024-06-01T12:00:00Z"),                       // created_at — safe
                json!(format!("ORD-{:06}", i)),                      // order_id — safe
                json!(29.99_f64),                                    // total — safe number
                json!("USD"),                                        // currency — safe
                json!(ambiguous_values[i % ambiguous_values.len()]), // notes — regex scan
            ])
        })
        .collect();

    json!({ "columns": columns, "rows": rows })
}

fn gate1_plan(sql: &str) -> RedactPlan {
    let extraction = extract_columns(sql);
    build_plan(
        &extraction,
        &Action::Redact,
        &WildcardPolicy::Warn,
        &common::config::PiiConfig::default().effective_column_denylist(),
    )
}

#[test]
fn gate1_plus_gate2_average_latency_under_10ms() {
    let payload = build_payload();
    let config = PiiConfig::default();

    // Warm up.
    let plan = gate1_plan(SQL);
    let _ = redact_with_stats(payload.clone(), &plan, &config);

    let mut total = std::time::Duration::ZERO;
    for _ in 0..ITERATIONS {
        let p = payload.clone();

        let start = Instant::now();
        let plan = gate1_plan(SQL); // Gate 1
        let _ = redact_with_stats(p, &plan, &config); // Gate 2
        total += start.elapsed();
    }

    let avg_ms = total.as_secs_f64() * 1000.0 / ITERATIONS as f64;
    println!(
        "\ngate1+gate2 average latency: {avg_ms:.2}ms  ({ROWS} rows, {ITERATIONS} iterations)"
    );
    assert!(
        avg_ms < TARGET_MS,
        "average latency {avg_ms:.2}ms exceeds {TARGET_MS}ms target"
    );
}
