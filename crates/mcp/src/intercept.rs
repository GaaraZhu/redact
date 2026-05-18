use common::config::PiiConfig;
use common::redactor::{redact_with_stats, RedactPlan};
use common::stats;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub type PendingCalls = Arc<Mutex<HashSet<String>>>;

pub fn new_pending_calls() -> PendingCalls {
    Arc::new(Mutex::new(HashSet::new()))
}

fn id_to_key(id: &Value) -> String {
    match id {
        Value::String(s) => format!("s:{s}"),
        Value::Number(n) => format!("n:{n}"),
        Value::Null => "null".to_string(),
        _ => serde_json::to_string(id).unwrap_or_default(),
    }
}

/// Returns true if this JSON-RPC message is a `tools/call` request.
pub fn is_tools_call_request(msg: &Value) -> bool {
    msg.get("method").and_then(|m| m.as_str()) == Some("tools/call") && msg.get("id").is_some()
}

/// Returns the serialised request ID, suitable for use as a HashMap key.
pub fn extract_request_id(msg: &Value) -> Option<String> {
    msg.get("id").map(id_to_key)
}

/// Returns true if `msg` is a JSON-RPC response whose ID is in `pending`, and
/// removes the ID from `pending`. Responses have no `method` field and carry
/// either `result` or `error`.
pub fn is_tracked_tools_call_response(msg: &Value, pending: &PendingCalls) -> bool {
    if msg.get("method").is_some() {
        return false;
    }
    let id_key = match msg.get("id") {
        Some(id) => id_to_key(id),
        None => return false,
    };
    if msg.get("result").is_none() && msg.get("error").is_none() {
        return false;
    }
    let mut guard = pending.lock().unwrap();
    if guard.contains(&id_key) {
        guard.remove(&id_key);
        true
    } else {
        false
    }
}

/// Build a JSON-RPC error response for a payload that exceeds `max_payload_bytes`.
///
/// Returning an error (rather than passing through) is the fail-closed behaviour:
/// the agent sees an explicit failure and can retry with a smaller query, while PII
/// in the oversized payload never reaches the model.
pub fn make_oversized_error(msg: &Value, size: usize, limit: usize) -> Value {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32603,
            "message": format!(
                "gate: payload {size} B exceeds max_payload_bytes {limit} B; \
                 query blocked to prevent unredacted PII reaching the model — \
                 reduce query size or raise max_payload_bytes in config"
            )
        }
    })
}

/// Redact PII from a `tools/call` response.
///
/// Runs Gate 2 over `result` (which contains `content[]`). The redactor's
/// JSONB scan handles text items that embed JSON strings, and the regex/Luhn
/// checks catch PII in plain-text items. A `_gate_summary` block is attached
/// to `result` by the existing `redact()` machinery.
///
/// When `record_as = Some(server_name)`, also appends an event to the
/// `gate retro` stats log labelled with that server name. Pass `None` to
/// skip stats recording (used by tests; production callers pass the
/// harness's logical server name).
///
/// Fails closed: if the redactor panics, returns an MCP error response.
pub fn redact_tools_call_response(
    mut msg: Value,
    config: &PiiConfig,
    record_as: Option<&str>,
) -> Value {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let msg_id = msg.get("id").cloned().unwrap_or(Value::Null);

    let redact_result = catch_unwind(AssertUnwindSafe(|| {
        let mut stats_out = None;
        if let Some(result) = msg.get_mut("result") {
            let result_value = result.take();
            let (redacted, rs) = redact_with_stats(result_value, &RedactPlan::empty(), config);
            *result = redacted;
            stats_out = Some(rs);
        }
        (msg, stats_out)
    }));

    match redact_result {
        Ok((redacted, stats_out)) => {
            if let (Some(server_name), Some(rs)) = (record_as, stats_out) {
                if rs.total > 0 {
                    let event = stats::Event::now("mcp", server_name, rs.total, rs.type_counts);
                    let _ = stats::record(&event);
                }
            }
            redacted
        }
        Err(_) => {
            eprintln!("[gate-mcp] redaction panicked; failing closed");
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": "gate: internal error during PII redaction"
                }
            })
        }
    }
}
