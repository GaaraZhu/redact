#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_gate");

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tmp() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn write_fake_server(dir: &TempDir, script_body: &str) -> String {
    let path = dir.path().join("fake-mcp-server.sh");
    fs::write(&path, format!("#!/bin/sh\n{script_body}")).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path.to_str().unwrap().to_string()
}

/// A fake MCP server that:
/// 1. Reads the initialize request, responds with capabilities.
/// 2. Reads the tools/call request, responds with content containing PII.
fn pii_server(dir: &TempDir) -> String {
    write_fake_server(
        dir,
        r#"read _req1
printf '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{},"protocolVersion":"2024-11-05","serverInfo":{"name":"fake","version":"1"}}}\n'
read _req2
printf '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"alice@example.com"}]}}\n'
"#,
    )
}

fn write_config(dir: &TempDir, yaml: &str) -> String {
    let path = dir.path().join("config.yaml");
    fs::write(&path, yaml).unwrap();
    path.to_str().unwrap().to_string()
}

fn no_config() -> String {
    "/tmp/gate_mcp_test_nonexistent_config_xyz_abc.yaml".to_string()
}

fn send_and_collect(server: &str, config: &str, requests: &[&str]) -> Vec<String> {
    let mut child = Command::new(BIN)
        .args(["mcp", "--", server])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .env("GATE_CONFIG", config)
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let stdout_pipe = child.stdout.take().unwrap();

    for req in requests {
        writeln!(stdin, "{req}").unwrap();
    }
    stdin.flush().unwrap();
    drop(stdin);

    let reader = BufReader::new(stdout_pipe);
    let lines: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.is_empty())
        .collect();

    child.wait().unwrap();
    lines
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn pii_in_tools_call_response_is_redacted() {
    let dir = tmp();
    let server = pii_server(&dir);
    let config = no_config();

    let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}"#;
    let tool_req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT email FROM users"}}}"#;

    let lines = send_and_collect(&server, &config, &[init_req, tool_req]);
    assert_eq!(lines.len(), 2, "expected 2 response lines, got: {lines:?}");

    // initialize response passes through unchanged
    assert!(lines[0].contains("\"id\":1"), "resp[0]={}", lines[0]);
    assert!(lines[0].contains("capabilities"), "resp[0]={}", lines[0]);

    // tools/call response has PII redacted
    assert!(lines[1].contains("\"id\":2"), "resp[1]={}", lines[1]);
    assert!(
        lines[1].contains("[PII:email]"),
        "email not redacted; resp[1]={}",
        lines[1]
    );
    assert!(
        !lines[1].contains("alice@example.com"),
        "raw email leaked; resp[1]={}",
        lines[1]
    );
    assert!(
        lines[1].contains("_gate_summary"),
        "_gate_summary missing; resp[1]={}",
        lines[1]
    );
}

#[test]
fn non_pii_response_passes_through_unchanged() {
    let dir = tmp();
    let server = write_fake_server(
        &dir,
        r#"read _req1
printf '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}\n'
read _req2
printf '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Query returned 5 rows"}]}}\n'
"#,
    );
    let config = no_config();

    let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let tool_req =
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"q","arguments":{}}}"#;

    let lines = send_and_collect(&server, &config, &[init_req, tool_req]);
    assert_eq!(lines.len(), 2);
    assert!(
        lines[1].contains("Query returned 5 rows"),
        "non-PII text was altered; resp[1]={}",
        lines[1]
    );
    // _gate_summary is always attached by the redactor; verify redacted count is 0
    assert!(
        lines[1].contains("\"redacted\":0"),
        "expected redacted:0 for clean result; resp[1]={}",
        lines[1]
    );
}

#[test]
fn upstream_exit_code_propagated() {
    let dir = tmp();
    let server = write_fake_server(&dir, "exit 3\n");

    let output = Command::new(BIN)
        .args(["mcp", "--", &server])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn redact_tool_results_false_disables_redaction() {
    let dir = tmp();
    let server = pii_server(&dir);
    let config = write_config(&dir, "mcp:\n  redact_tool_results: false\n");

    let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let tool_req =
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"q","arguments":{}}}"#;

    let lines = send_and_collect(&server, &config, &[init_req, tool_req]);
    assert_eq!(lines.len(), 2);
    assert!(
        lines[1].contains("alice@example.com"),
        "passthrough mode should not redact; resp[1]={}",
        lines[1]
    );
}

#[test]
fn oversized_payload_returns_error() {
    let dir = tmp();
    let server = pii_server(&dir);
    // 1-byte limit forces the size check to trip for any non-trivial response
    let config = write_config(&dir, "mcp:\n  max_payload_bytes: 1\n");

    let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let tool_req =
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"q","arguments":{}}}"#;

    let lines = send_and_collect(&server, &config, &[init_req, tool_req]);
    assert_eq!(lines.len(), 2);
    // Must be an error response, not the raw payload
    assert!(
        lines[1].contains("\"error\""),
        "oversized payload should return an error, not pass through; resp[1]={}",
        lines[1]
    );
    assert!(
        !lines[1].contains("alice@example.com"),
        "oversized payload leaked PII; resp[1]={}",
        lines[1]
    );
    assert!(
        lines[1].contains("max_payload_bytes"),
        "error message should mention max_payload_bytes; resp[1]={}",
        lines[1]
    );
}
