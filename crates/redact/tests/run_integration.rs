use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_redact");

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tmp() -> TempDir {
    tempfile::tempdir().unwrap()
}

/// Write a YAML config file into `dir` and return its path string.
fn write_config(dir: &TempDir, yaml: &str) -> String {
    let path = dir.path().join("config.yaml");
    fs::write(&path, yaml).unwrap();
    path.to_str().unwrap().to_string()
}

/// Write an executable shell script into `dir` and return its path string.
fn write_script(dir: &TempDir, name: &str, body: &str) -> String {
    let path = dir.path().join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path.to_str().unwrap().to_string()
}

fn redact_run(config: &str, tool: &str, extra: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .arg("run")
        .arg("--")
        .arg(tool)
        .args(extra)
        .env("REDACT_CONFIG", config)
        .output()
        .unwrap()
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn exit_code(o: &std::process::Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// tkpsql-shaped output: object with `rows` + `count`.
/// Gate 2 redacts email and ssn; Gate 1 also force-marks them via forced_columns.
#[test]
fn tkpsql_shape_redacts_pii_and_attaches_summary() {
    let dir = tmp();
    let tool = write_script(
        &dir,
        "fake-tkpsql",
        r#"echo '{"rows":[{"id":1,"email":"alice@example.com","ssn":"123-45-6789"}],"count":1}'"#,
    );
    let config = write_config(&dir, "tools:\n  fake-tkpsql:\n    sql_arg: \"--sql\"\n");

    let out = redact_run(
        &config,
        &tool,
        &["--sql", "SELECT id, email, ssn FROM users"],
    );

    assert_eq!(exit_code(&out), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["rows"][0]["id"], 1);
    assert_eq!(v["rows"][0]["email"], "[PII:email]");
    assert_eq!(v["rows"][0]["ssn"], "[PII:ssn]");
    assert_eq!(v["count"], 1);
    assert_eq!(v["_redact_summary"]["redacted"], 2);
}

/// mysql-shaped output: bare JSON array.
/// With include_summary=true (default), array is wrapped as {"rows": ..., "_redact_summary": ...}.
#[test]
fn mysql_shape_bare_array_wrapped_with_summary() {
    let dir = tmp();
    let tool = write_script(
        &dir,
        "fake-mysql",
        r#"echo '[{"id":1,"email":"bob@example.com"}]'"#,
    );
    let config = write_config(&dir, "tools:\n  fake-mysql:\n    sql_arg: \"-e\"\n");

    let out = redact_run(&config, &tool, &["-e", "SELECT id, email FROM users"]);

    assert_eq!(exit_code(&out), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["rows"][0]["email"], "[PII:email]");
    assert!(v.get("_redact_summary").is_some());
}

/// Error JSON from the tool must pass through unchanged — no summary attached.
#[test]
fn error_json_passes_through_unchanged() {
    let dir = tmp();
    let tool = write_script(&dir, "fake-tool", r#"echo '{"error":"permission denied"}'"#);
    let config = write_config(&dir, "tools:\n  fake-tool:\n    sql_arg: \"--sql\"\n");

    let out = redact_run(&config, &tool, &["--sql", "SELECT 1"]);

    assert_eq!(exit_code(&out), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["error"], "permission denied");
    assert!(v.get("_redact_summary").is_none());
}

/// Non-JSON stdout must be forwarded to our stdout verbatim.
#[test]
fn non_json_output_forwarded_unchanged() {
    let dir = tmp();
    let tool = write_script(&dir, "fake-tool", "printf 'plain text output'");
    let config = write_config(&dir, "tools:\n  fake-tool:\n    sql_arg: \"--sql\"\n");

    let out = redact_run(&config, &tool, &["--sql", "SELECT 1"]);

    assert_eq!(exit_code(&out), 0);
    assert_eq!(stdout(&out), "plain text output");
}

/// Non-zero subprocess exit code must be propagated; stdout is forwarded unchanged.
#[test]
fn non_zero_exit_code_propagated() {
    let dir = tmp();
    let tool = write_script(&dir, "fake-tool", "echo 'something failed'\nexit 2");
    let config = write_config(&dir, "tools:\n  fake-tool:\n    sql_arg: \"--sql\"\n");

    let out = redact_run(&config, &tool, &["--sql", "SELECT 1"]);

    assert_eq!(exit_code(&out), 2);
    assert!(stdout(&out).contains("something failed"));
}

/// Tool not in config: output still goes through Gate 2 (column-name + regex).
/// No Gate 1 plan, but Gate 2 catches email via regex/column-name heuristics.
#[test]
fn unconfigured_tool_still_runs_gate2() {
    let dir = tmp();
    let tool = write_script(
        &dir,
        "other-tool",
        r#"echo '{"email":"carol@example.com"}'"#,
    );
    // Config has no entry for `other-tool`
    let config = write_config(&dir, "");

    let out = redact_run(&config, &tool, &[]);

    assert_eq!(exit_code(&out), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["email"], "[PII:email]");
}

/// Gate 1 rejection: SELECT * with wildcard_policy=reject must
/// exit 1 with an error JSON before the tool is ever spawned.
#[test]
fn gate1_wildcard_reject_prevents_execution() {
    let dir = tmp();
    // Tool would output PII if spawned — but it must not be spawned at all.
    let tool = write_script(
        &dir,
        "fake-tkpsql",
        r#"echo '{"rows":[{"email":"alice@example.com"}]}'"#,
    );
    let config = write_config(
        &dir,
        "tools:\n  fake-tkpsql:\n    sql_arg: \"--sql\"\npii:\n  wildcard_policy: reject\n",
    );

    let out = redact_run(&config, &tool, &["--sql", "SELECT * FROM users"]);

    assert_eq!(exit_code(&out), 1);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert!(v.get("error").is_some());
}

/// Gate 1 forced column: alias `contact` is mapped to original `email`.
/// Gate 2 sees `forced_columns["contact"] = "email"` and redacts the value
/// even though `contact` alone would not trigger the column-name heuristic.
#[test]
fn gate1_forced_alias_redacted_by_gate2() {
    let dir = tmp();
    // Value `not-an-email` doesn't match the email regex, so without the
    // forced_columns entry Gate 2 would pass it through.
    let tool = write_script(&dir, "fake-tkpsql", r#"echo '{"contact":"not-an-email"}'"#);
    let config = write_config(
        &dir,
        "tools:\n  fake-tkpsql:\n    sql_arg: \"--sql\"\npii:\n  wildcard_policy: warn\n",
    );

    let out = redact_run(
        &config,
        &tool,
        &["--sql", "SELECT email AS contact FROM users"],
    );

    assert_eq!(exit_code(&out), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["contact"], "[PII:email]");
}

/// Leading KEY=VALUE env-var tokens must be passed to the subprocess, not treated as
/// the command name (regression: previously caused "No such file or directory" error).
#[test]
fn env_var_prefix_passed_to_subprocess() {
    let dir = tmp();
    // Tool echoes the value of MY_SECRET so we can assert it was received.
    let tool = write_script(&dir, "fake-tool", r#"echo "{\"got\":\"$MY_SECRET\"}""#);
    let config = write_config(&dir, "tools:\n  fake-tool:\n    sql_arg: \"--sql\"\n");

    let out = Command::new(BIN)
        .arg("run")
        .arg("--")
        .arg("MY_SECRET=hunter2")
        .arg(&tool)
        .arg("--sql")
        .arg("SELECT id FROM users")
        .env("REDACT_CONFIG", &config)
        .output()
        .unwrap();

    assert_eq!(exit_code(&out), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["got"], "hunter2");
}

/// json_tool rewrite: run.rs must spawn the wrapper binary (not the original tool) and
/// translate the sql_arg flag to --sql. The original tool binary is intentionally absent;
/// if run.rs mistakenly tries to spawn it, the test fails with ENOENT.
#[test]
fn json_tool_binary_spawned_and_sql_arg_translated() {
    let dir = tmp();
    let json_wrapper = write_script(
        &dir,
        "psql-json",
        r#"echo '{"rows":[{"id":1,"email":"alice@example.com"}],"count":1}'"#,
    );
    let config = write_config(
        &dir,
        &format!("tools:\n  psql:\n    sql_arg: \"-c\"\n    json_tool: \"{json_wrapper}\"\n"),
    );
    // Pass a non-existent psql path — if run.rs spawns it instead of the wrapper, ENOENT.
    let fake_psql = dir.path().join("psql").to_str().unwrap().to_string();
    let out = redact_run(
        &config,
        &fake_psql,
        &["-U", "redact", "-c", "SELECT id, email FROM users"],
    );

    assert_eq!(
        exit_code(&out),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["rows"][0]["email"], "[PII:email]");
    assert_eq!(v["rows"][0]["id"], 1);
    assert_eq!(v["_redact_summary"]["redacted"], 1);
}

/// json_tool rewrite with equals-form flag (-c=VALUE) must also be translated to --sql=VALUE.
#[test]
fn json_tool_equals_form_flag_translated() {
    let dir = tmp();
    let json_wrapper = write_script(
        &dir,
        "psql-json",
        r#"echo '{"rows":[{"id":2,"email":"bob@example.com"}],"count":1}'"#,
    );
    let config = write_config(
        &dir,
        &format!("tools:\n  psql:\n    sql_arg: \"-c\"\n    json_tool: \"{json_wrapper}\"\n"),
    );
    let fake_psql = dir.path().join("psql").to_str().unwrap().to_string();
    let out = redact_run(&config, &fake_psql, &["-c=SELECT id, email FROM users"]);

    assert_eq!(
        exit_code(&out),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["rows"][0]["email"], "[PII:email]");
}

/// Wrapper prefix: tool is at position 1 (e.g. `rtk psql`). run.rs must find it via
/// find_tool_token, apply Gate 1 using psql's sql_arg, and spawn the wrapper correctly.
#[test]
fn wrapper_prefix_tool_detected_and_redacted() {
    let dir = tmp();
    let psql_json = write_script(
        &dir,
        "psql-json",
        r#"echo '{"rows":[{"id":1,"email":"alice@example.com"}]}'"#,
    );
    // wrapper: executes its arguments
    let wrapper = write_script(&dir, "wrapper", r#""$@""#);
    let config = write_config(
        &dir,
        &format!("tools:\n  psql:\n    sql_arg: \"-c\"\n    json_tool: \"{psql_json}\"\n"),
    );
    // cmd_args = [wrapper, fake_psql, "-c", "SELECT id, email FROM users"]
    // tool_idx=1 (psql), json_tool rewrites fake_psql → psql_json, wrapper spawns it
    let fake_psql = dir.path().join("psql").to_str().unwrap().to_string();
    let out = redact_run(
        &config,
        &wrapper,
        &[&fake_psql, "-c", "SELECT id, email FROM users"],
    );

    assert_eq!(
        exit_code(&out),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["rows"][0]["email"], "[PII:email]");
    assert_eq!(v["rows"][0]["id"], 1);
}

/// `--sql=VALUE` form (equals sign) must be parsed correctly by find_flag_value.
#[test]
fn sql_flag_equals_form_parsed() {
    let dir = tmp();
    let tool = write_script(
        &dir,
        "fake-tkpsql",
        r#"echo '{"email":"dave@example.com"}'"#,
    );
    let config = write_config(&dir, "tools:\n  fake-tkpsql:\n    sql_arg: \"--sql\"\n");

    let out = redact_run(&config, &tool, &["--sql=SELECT email FROM users"]);

    assert_eq!(exit_code(&out), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["email"], "[PII:email]");
}
