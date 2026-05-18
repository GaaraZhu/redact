use mcp::intercept::{
    extract_request_id, is_tools_call_request, is_tracked_tools_call_response,
    make_oversized_error, new_pending_calls, redact_tools_call_response,
};
use serde_json::{json, Value};

fn pii_config() -> common::config::PiiConfig {
    common::config::PiiConfig::default()
}

// ── Request detection ─────────────────────────────────────────────────────────

#[test]
fn tools_call_request_detected() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "query", "arguments": {"sql": "SELECT email FROM users"}}
    });
    assert!(is_tools_call_request(&msg));
}

#[test]
fn tools_list_request_not_detected() {
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    assert!(!is_tools_call_request(&msg));
}

#[test]
fn notification_without_id_not_detected() {
    let msg = json!({"jsonrpc": "2.0", "method": "tools/call", "params": {}});
    assert!(!is_tools_call_request(&msg));
}

// ── Response tracking ─────────────────────────────────────────────────────────

#[test]
fn response_matched_to_tracked_id_and_removed() {
    let pending = new_pending_calls();
    let req = json!({"jsonrpc": "2.0", "id": 42, "method": "tools/call", "params": {}});
    pending
        .lock()
        .unwrap()
        .insert(extract_request_id(&req).unwrap());

    let resp = json!({"jsonrpc": "2.0", "id": 42, "result": {"content": []}});
    assert!(is_tracked_tools_call_response(&resp, &pending));
    // ID removed — second call returns false
    assert!(!is_tracked_tools_call_response(&resp, &pending));
}

#[test]
fn response_with_untracked_id_not_matched() {
    let pending = new_pending_calls();
    let resp = json!({"jsonrpc": "2.0", "id": 99, "result": {"content": []}});
    assert!(!is_tracked_tools_call_response(&resp, &pending));
}

#[test]
fn request_not_matched_as_response() {
    let pending = new_pending_calls();
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}});
    pending
        .lock()
        .unwrap()
        .insert(extract_request_id(&req).unwrap());
    // The request itself is not a response (has method field)
    assert!(!is_tracked_tools_call_response(&req, &pending));
}

#[test]
fn string_id_tracked_correctly() {
    let pending = new_pending_calls();
    let req = json!({"jsonrpc": "2.0", "id": "req-abc", "method": "tools/call", "params": {}});
    pending
        .lock()
        .unwrap()
        .insert(extract_request_id(&req).unwrap());
    let resp = json!({"jsonrpc": "2.0", "id": "req-abc", "result": {"content": []}});
    assert!(is_tracked_tools_call_response(&resp, &pending));
}

// ── Redaction ─────────────────────────────────────────────────────────────────

#[test]
fn json_text_content_is_redacted() {
    let pending = new_pending_calls();
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}});
    pending
        .lock()
        .unwrap()
        .insert(extract_request_id(&req).unwrap());

    let resp = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{
                "type": "text",
                "text": "{\"email\": \"alice@example.com\", \"id\": 1}"
            }]
        }
    });

    let redacted = redact_tools_call_response(resp, &pii_config(), None);
    let text_str = redacted["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text_str).unwrap();
    assert_eq!(parsed["email"], "[PII:email]");
    assert_eq!(parsed["id"], 1);
    // _gate_summary is attached to result by redact(), not embedded in the text JSON
    assert!(redacted["result"].get("_gate_summary").is_some());
}

#[test]
fn raw_email_in_text_content_is_redacted() {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "content": [{"type": "text", "text": "alice@example.com"}]
        }
    });
    let redacted = redact_tools_call_response(resp, &pii_config(), None);
    let text = redacted["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, "[PII:email]");
}

#[test]
fn non_pii_text_passes_through_unchanged() {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "content": [{"type": "text", "text": "Query returned 5 rows"}]
        }
    });
    let redacted = redact_tools_call_response(resp, &pii_config(), None);
    assert_eq!(
        redacted["result"]["content"][0]["text"],
        "Query returned 5 rows"
    );
}

#[test]
fn image_content_passes_through_unchanged() {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "result": {
            "content": [{
                "type": "image",
                "data": "base64encodeddata==",
                "mimeType": "image/png"
            }]
        }
    });
    let original_content = resp["result"]["content"].clone();
    let redacted = redact_tools_call_response(resp, &pii_config(), None);
    // Image item is unchanged
    assert_eq!(
        redacted["result"]["content"][0]["data"],
        original_content[0]["data"]
    );
}

#[test]
fn ssn_in_json_text_is_redacted() {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "result": {
            "content": [{
                "type": "text",
                "text": "{\"ssn\": \"123-45-6789\", \"name\": \"Alice\"}"
            }]
        }
    });
    let redacted = redact_tools_call_response(resp, &pii_config(), None);
    let text_str = redacted["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text_str).unwrap();
    assert_eq!(parsed["ssn"], "[PII:ssn]");
}

#[test]
fn multiple_content_items_all_redacted() {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "result": {
            "content": [
                {"type": "text", "text": "alice@example.com"},
                {"type": "text", "text": "bob@example.com"}
            ]
        }
    });
    let redacted = redact_tools_call_response(resp, &pii_config(), None);
    assert_eq!(redacted["result"]["content"][0]["text"], "[PII:email]");
    assert_eq!(redacted["result"]["content"][1]["text"], "[PII:email]");
}

#[test]
fn response_without_result_passes_through() {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "error": {"code": -32601, "message": "method not found"}
    });
    let redacted = redact_tools_call_response(resp.clone(), &pii_config(), None);
    assert_eq!(redacted["error"]["code"], -32601);
}

#[test]
fn gate_summary_attached_to_result_on_redaction() {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "result": {
            "content": [{"type": "text", "text": "alice@example.com"}]
        }
    });
    let redacted = redact_tools_call_response(resp, &pii_config(), None);
    // _gate_summary is added to result by the redactor
    assert!(redacted["result"].get("_gate_summary").is_some());
    assert_eq!(redacted["result"]["_gate_summary"]["redacted"], 1);
}

// ── Oversized payload blocking ────────────────────────────────────────────────

#[test]
fn oversized_payload_returns_error_not_passthrough() {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "result": {
            "content": [{"type": "text", "text": "alice@example.com"}]
        }
    });
    let size = serde_json::to_string(&resp).unwrap().len();
    let error_resp = make_oversized_error(&resp, size, 10);
    assert_eq!(error_resp["id"], 42);
    assert!(
        error_resp.get("result").is_none(),
        "must not pass result through"
    );
    assert!(error_resp.get("error").is_some(), "must return an error");
    assert_eq!(error_resp["error"]["code"], -32603);
    let msg = error_resp["error"]["message"].as_str().unwrap();
    assert!(msg.contains("max_payload_bytes"));
}

#[test]
fn oversized_error_preserves_string_id() {
    let resp = json!({"jsonrpc": "2.0", "id": "req-xyz", "result": {}});
    let error_resp = make_oversized_error(&resp, 9999, 100);
    assert_eq!(error_resp["id"], "req-xyz");
}

// ── Passthrough for non-tools/call messages ───────────────────────────────────

#[test]
fn initialize_response_passes_through() {
    let pending = new_pending_calls();
    // No tools/call request was tracked, so this response is not intercepted
    let resp = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "test-server", "version": "1.0.0"}
        }
    });
    assert!(!is_tracked_tools_call_response(&resp, &pending));
}
