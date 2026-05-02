use common::{
    config::PiiConfig,
    redactor::{redact, RedactPlan},
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::{json, Value};

// NFR-1: Gate 2 must process 1000 rows × 50 cols in < 100ms.
fn build_payload() -> Value {
    let safe_cols = [
        "id",
        "status",
        "category",
        "region",
        "product_code",
        "order_id",
        "sku",
        "quantity",
        "price",
        "discount",
        "tax",
        "currency",
        "channel",
        "source",
        "campaign",
        "referrer",
        "session_id",
        "device",
        "os",
        "browser",
        "country",
        "state",
        "zip_region",
        "warehouse",
        "carrier",
    ];
    let pii_cols = [
        "email",
        "ssn",
        "phone",
        "credit_card",
        "dob",
        "first_name",
        "last_name",
        "address",
        "passport",
        "license_number",
        "npi",
        "card_number",
        "cvv",
        "birthdate",
        "full_name",
        "mobile",
        "mail",
        "contact_email",
        "user_phone",
        "home_address",
        "billing_address",
        "national_id",
        "tax_id",
        "bank_account",
        "routing_number",
    ];

    let safe_values = [
        "active",
        "inactive",
        "pending",
        "retail",
        "wholesale",
        "US",
        "EU",
        "WIDGET-001",
        "ORD-12345",
        "SKU-99",
        "10",
        "29.99",
        "0.10",
        "2.50",
        "USD",
        "online",
        "direct",
        "CAMP-001",
        "ref123",
        "sess-abc",
        "mobile",
        "ios",
        "safari",
        "US",
        "CA",
    ];

    let rows: Vec<Value> = (0..1000)
        .map(|i| {
            let mut obj = serde_json::Map::new();
            for (j, col) in safe_cols.iter().enumerate() {
                let val = safe_values[j % safe_values.len()];
                obj.insert(col.to_string(), json!(val));
            }
            for col in &pii_cols {
                // Use obviously non-PII values so Gate 2 runs all regex paths (worst-case path).
                obj.insert(col.to_string(), json!(format!("value-{i}")));
            }
            Value::Object(obj)
        })
        .collect();

    json!(rows)
}

fn bench_gate2_1000x50(c: &mut Criterion) {
    let payload = build_payload();
    let plan = RedactPlan::empty();
    let config = PiiConfig::default();

    c.bench_function("gate2_1000rows_50cols", |b| {
        b.iter(|| {
            let p = payload.clone();
            black_box(redact(black_box(p), &plan, &config))
        });
    });
}

criterion_group!(benches, bench_gate2_1000x50);
criterion_main!(benches);
