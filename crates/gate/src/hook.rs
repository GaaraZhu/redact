// Snake_case PreToolUse JSON is the single on-the-wire shape for gate hook.
// Claude Code sends it directly; the opencode plugin (written by `gate init --harness opencode`)
// translates opencode's tool.execute.before(input, output) arguments into this same shape before
// piping to stdin. No opencode-specific Rust path is needed.
use crate::command;
use common::config::Config;
use serde_json::{json, Value};
use std::io::{self, Read};

pub fn run() {
    let mut stdin = String::new();
    io::stdin().read_to_string(&mut stdin).unwrap_or_default();

    // Load config; on failure passthrough so a bad config never blocks every Bash command
    let config = Config::load().unwrap_or_default();

    if let Some(output) = process(&stdin, &config) {
        print!("{}", output);
    }
    // No output → passthrough (Claude Code allows the original command)
}

fn is_disabled_by_env() -> bool {
    std::env::var("GATE_DISABLED")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Returns `Some(json_string)` to rewrite, `None` to pass through unchanged.
fn process(stdin: &str, config: &Config) -> Option<String> {
    if !config.enabled || is_disabled_by_env() {
        return None;
    }

    let hook_input: Value = serde_json::from_str(stdin).ok()?;

    let command = hook_input
        .get("tool_input")
        .and_then(|ti| ti.get("command"))
        .and_then(|c| c.as_str())?
        .to_string();

    let tokens = shell_words::split(&command)
        .ok()
        .filter(|t| !t.is_empty())?;

    // Loop avoidance: check the first non-env-var token
    let first_cmd = tokens
        .iter()
        .find(|t| !t.contains('=') || t.starts_with('-'))?;
    let first_basename = command::token_basename(first_cmd);
    if first_basename == "gate" {
        let idx = tokens.iter().position(|t| t == first_cmd).unwrap_or(0);
        if tokens.get(idx + 1).map(String::as_str) == Some("run") {
            return None;
        }
    }

    // Find the configured tool anywhere in the positional tokens (may be preceded by wrappers)
    let tool_match = command::find_tool_token(&tokens, config)?;
    let basename = match &tool_match {
        command::ToolMatch::Direct { basename, .. } => basename,
        command::ToolMatch::Nested { basename } => basename,
    };
    let tool_config = config.tools.get(basename)?;

    // For nested invocations (tool inside `sh -c "..."`) skip json_tool rewriting —
    // the json_tool binary may not exist in the target environment (container/pod).
    let effective_command = match &tool_match {
        command::ToolMatch::Direct { idx, .. } => {
            match (&tool_config.json_tool, &tool_config.sql_arg) {
                (Some(json_tool), Some(sql_arg)) => {
                    rewrite_to_json_tool(&tokens, *idx, sql_arg, json_tool)
                }
                _ => command.clone(),
            }
        }
        command::ToolMatch::Nested { .. } => command.clone(),
    };

    // Rewrite: preserve all tool_input fields, replace command
    let mut updated_input = hook_input["tool_input"].clone();
    if let Some(obj) = updated_input.as_object_mut() {
        obj.insert(
            "command".to_string(),
            json!(format!("gate run -- {}", effective_command)),
        );
    }

    Some(
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": updated_input,
            }
        })
        .to_string(),
    )
}

/// Rewrite `tokens` so that the token at `tool_idx` is replaced with `json_tool` and
/// `sql_arg` (in both `--flag VALUE` and `--flag=VALUE` forms) is replaced with `--sql`.
/// Returns the reconstructed shell-quoted command string.
fn rewrite_to_json_tool(
    tokens: &[String],
    tool_idx: usize,
    sql_arg: &str,
    json_tool: &str,
) -> String {
    let eq_prefix = format!("{sql_arg}=");
    let new_tokens: Vec<String> = tokens
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if i == tool_idx {
                json_tool.to_string()
            } else if t == sql_arg {
                "--sql".to_string()
            } else if let Some(val) = t.strip_prefix(&eq_prefix) {
                format!("--sql={val}")
            } else {
                t.clone()
            }
        })
        .collect();
    shell_words::join(&new_tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::config::ToolConfig;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    fn make_config(entries: &[(&str, Option<&str>, Option<&str>)]) -> Config {
        let tools = entries
            .iter()
            .map(|(name, sql_arg, json_tool)| {
                (
                    name.to_string(),
                    ToolConfig {
                        sql_arg: sql_arg.map(String::from),
                        json_tool: json_tool.map(String::from),
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        Config {
            tools,
            ..Config::default()
        }
    }

    fn default_config() -> Config {
        make_config(&[
            ("tkpsql", Some("--sql"), None),
            ("tkdbr", Some("--sql"), None),
            ("mysql", Some("-e"), None),
            ("psql", Some("-c"), None),
        ])
    }

    fn make_input(command: &str) -> String {
        json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command }
        })
        .to_string()
    }

    #[test]
    fn passthrough_when_config_disabled() {
        let _guard = LOCK.lock().unwrap();
        let mut config = default_config();
        config.enabled = false;
        // Even a normally-intercepted tool must passthrough when disabled.
        assert!(process(
            &make_input("tkpsql --sql 'SELECT email FROM users'"),
            &config
        )
        .is_none());
    }

    #[test]
    fn passthrough_when_env_disabled() {
        let _guard = LOCK.lock().unwrap();
        unsafe { std::env::set_var("GATE_DISABLED", "1") };
        let result = process(
            &make_input("tkpsql --sql 'SELECT email FROM users'"),
            &default_config(),
        );
        unsafe { std::env::remove_var("GATE_DISABLED") };
        assert!(result.is_none());
    }

    #[test]
    fn env_disabled_true_string() {
        let _guard = LOCK.lock().unwrap();
        unsafe { std::env::set_var("GATE_DISABLED", "true") };
        let result = process(
            &make_input("tkpsql --sql 'SELECT email FROM users'"),
            &default_config(),
        );
        unsafe { std::env::remove_var("GATE_DISABLED") };
        assert!(result.is_none());
    }

    #[test]
    fn env_disabled_zero_does_not_disable() {
        let _guard = LOCK.lock().unwrap();
        unsafe { std::env::set_var("GATE_DISABLED", "0") };
        let result = process(
            &make_input("tkpsql --sql 'SELECT email FROM users'"),
            &default_config(),
        );
        unsafe { std::env::remove_var("GATE_DISABLED") };
        assert!(result.is_some(), "GATE_DISABLED=0 must not disable gate");
    }

    #[test]
    fn passthrough_non_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        assert!(process(&make_input("ls -la"), &config).is_none());
        assert!(process(&make_input("grep foo bar.txt"), &config).is_none());
    }

    #[test]
    fn rewrite_tkpsql() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input("tkpsql --sql 'SELECT email FROM users'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run -- tkpsql"));
        assert!(cmd.contains("SELECT email FROM users"));
    }

    #[test]
    fn rewrite_tkdbr() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input("tkdbr --sql 'SELECT phone FROM contacts'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run -- tkdbr"));
    }

    #[test]
    fn rewrite_mysql() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(&make_input("mysql -e 'SELECT ssn FROM patients'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run -- mysql"));
    }

    #[test]
    fn rewrite_psql() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(&make_input("psql -c 'SELECT phone FROM contacts'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run -- psql"));
    }

    #[test]
    fn loop_avoidance() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        assert!(process(&make_input("gate run -- tkpsql --sql 'SELECT 1'"), &config).is_none());
    }

    #[test]
    fn invalid_json_passthrough() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        assert!(process("not json at all", &config).is_none());
    }

    #[test]
    fn permission_decision_is_allow() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(&make_input("psql -c 'SELECT phone FROM contacts'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecision"]
                .as_str()
                .unwrap(),
            "allow"
        );
    }

    #[test]
    fn full_path_basename_matched() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        assert!(process(
            &make_input("/usr/local/bin/tkpsql --sql 'SELECT 1'"),
            &config
        )
        .is_some());
    }

    #[test]
    fn passthrough_when_tool_not_in_config() {
        let _guard = LOCK.lock().unwrap();
        let config = make_config(&[]);
        assert!(process(
            &make_input("tkpsql --sql 'SELECT email FROM users'"),
            &config
        )
        .is_none());
    }

    #[test]
    fn command_with_quoted_sql_preserved() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input(r#"tkpsql --sql "SELECT 'a b' FROM t""#),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("SELECT 'a b'") || cmd.contains(r#"SELECT \'a b\'"#));
    }

    #[test]
    fn malformed_shell_words_passthrough() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let input = make_input("tkpsql --sql 'unclosed");
        assert!(process(&input, &config).is_none());
    }

    #[test]
    fn env_var_prefix_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        // PGPASSWORD=x prefix must not prevent psql from being detected
        let out = process(
            &make_input("PGPASSWORD=secret psql -c 'SELECT email FROM users'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run -- PGPASSWORD=secret psql"));
    }

    #[test]
    fn multiple_env_vars_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input("PGPASSWORD=x PGSSLMODE=require psql -c 'SELECT id FROM t'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("psql"));
    }

    #[test]
    fn preserves_extra_tool_input_fields() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let input = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "tkpsql --sql 'SELECT 1'",
                "restart": false
            }
        })
        .to_string();
        let out = process(&input, &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["hookSpecificOutput"]["updatedInput"]["restart"],
            json!(false)
        );
    }

    // ── wrapper-prefix tests ──────────────────────────────────────────────────

    #[test]
    fn single_wrapper_prefix_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input("rtk psql -c 'SELECT email FROM users'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run -- rtk psql"), "got: {cmd}");
    }

    #[test]
    fn multiple_wrapper_prefixes_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input("wrapper1 wrapper2 psql -c 'SELECT id FROM t'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(
            cmd.starts_with("gate run -- wrapper1 wrapper2 psql"),
            "got: {cmd}"
        );
    }

    #[test]
    fn tool_as_flag_value_not_intercepted() {
        let _guard = LOCK.lock().unwrap();
        // psql appears as the value of --db, not as a command — must passthrough
        let config = default_config();
        assert!(
            process(&make_input("some-tool --db psql -c 'SELECT id'"), &config).is_none(),
            "should not intercept when tool name is a flag value"
        );
    }

    #[test]
    fn wrapper_prefix_with_json_tool_rewrites_correctly() {
        let _guard = LOCK.lock().unwrap();
        let config = make_config(&[("psql", Some("-c"), Some("psql-json"))]);
        let out = process(
            &make_input("rtk psql -c 'SELECT email FROM users'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("rtk"), "wrapper must be preserved: {cmd}");
        assert!(cmd.contains("psql-json"), "tool must be rewritten: {cmd}");
        assert!(cmd.contains("--sql"), "flag must be translated: {cmd}");
        assert!(!cmd.contains(" psql "), "original tool must be gone: {cmd}");
    }

    // ── json_tool rewrite tests ───────────────────────────────────────────────

    #[test]
    fn json_tool_rewrites_binary_and_flag() {
        let _guard = LOCK.lock().unwrap();
        let config = make_config(&[("psql", Some("-c"), Some("psql-json"))]);
        let out = process(&make_input("psql -c 'SELECT email FROM users'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        // Binary replaced and flag translated
        assert!(cmd.contains("psql-json"), "expected psql-json in: {cmd}");
        assert!(cmd.contains("--sql"), "expected --sql in: {cmd}");
        assert!(
            !cmd.contains("psql-json-json"),
            "double-rewrite guard: {cmd}"
        );
    }

    #[test]
    fn json_tool_flag_equals_form() {
        let _guard = LOCK.lock().unwrap();
        let config = make_config(&[("psql", Some("-c"), Some("psql-json"))]);
        let out = process(&make_input("psql -c='SELECT id FROM t'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("--sql="), "expected --sql= in: {cmd}");
    }

    #[test]
    fn json_tool_preserves_env_var_prefix() {
        let _guard = LOCK.lock().unwrap();
        let config = make_config(&[("psql", Some("-c"), Some("psql-json"))]);
        let out = process(
            &make_input("PGPASSWORD=secret psql -c 'SELECT id FROM t'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("PGPASSWORD=secret"), "env var lost: {cmd}");
        assert!(cmd.contains("psql-json"), "binary not rewritten: {cmd}");
        assert!(cmd.contains("--sql"), "flag not rewritten: {cmd}");
    }

    #[test]
    fn json_tool_mysql_rewrite() {
        let _guard = LOCK.lock().unwrap();
        let config = make_config(&[("mysql", Some("-e"), Some("mysql-json"))]);
        let out = process(&make_input("mysql -e 'SELECT email FROM users'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("mysql-json"), "expected mysql-json in: {cmd}");
        assert!(cmd.contains("--sql"), "expected --sql in: {cmd}");
    }

    #[test]
    fn json_tool_sqlcmd_rewrite() {
        let _guard = LOCK.lock().unwrap();
        let config = make_config(&[("sqlcmd", Some("-Q"), Some("sqlcmd-json"))]);
        let out = process(&make_input("sqlcmd -Q 'SELECT email FROM users'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(
            cmd.contains("sqlcmd-json"),
            "expected sqlcmd-json in: {cmd}"
        );
        assert!(cmd.contains("--sql"), "expected --sql in: {cmd}");
    }

    #[test]
    fn no_json_tool_uses_original_command() {
        let _guard = LOCK.lock().unwrap();
        // Tool in config but no json_tool: original command passed to gate run unchanged
        let config = make_config(&[("psql", Some("-c"), None)]);
        let out = process(&make_input("psql -c 'SELECT id FROM t'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run -- psql"), "unexpected cmd: {cmd}");
        assert!(!cmd.contains("psql-json"), "should not rewrite: {cmd}");
    }

    // ── shell interpreter (-c) tests ──────────────────────────────────────────

    #[test]
    fn sh_c_psql_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input(r#"sh -c "psql -c 'SELECT email FROM users'""#),
            &config,
        );
        assert!(out.is_some(), "sh -c psql must be intercepted");
        let v: Value = serde_json::from_str(&out.unwrap()).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run --"), "got: {cmd}");
    }

    #[test]
    fn bash_c_psql_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input(r#"bash -c "psql -c 'SELECT email FROM users'""#),
            &config,
        );
        assert!(out.is_some(), "bash -c psql must be intercepted");
    }

    #[test]
    fn docker_exec_sh_c_psql_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input(r#"docker exec mycontainer sh -c "psql -c 'SELECT email FROM users'""#),
            &config,
        );
        assert!(out.is_some(), "docker exec sh -c psql must be intercepted");
        let v: Value = serde_json::from_str(&out.unwrap()).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run --"), "got: {cmd}");
    }

    #[test]
    fn sh_c_nested_skips_json_tool_rewrite() {
        let _guard = LOCK.lock().unwrap();
        // json_tool rewrite is skipped for nested invocations: psql-json may not exist
        // in the target environment (remote container/pod)
        let config = make_config(&[("psql", Some("-c"), Some("psql-json"))]);
        let out = process(
            &make_input(r#"sh -c "psql -c 'SELECT email FROM users'""#),
            &config,
        );
        assert!(out.is_some(), "must be intercepted");
        let v: Value = serde_json::from_str(&out.unwrap()).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run --"), "got: {cmd}");
        assert!(
            !cmd.contains("psql-json"),
            "must not rewrite to json_tool for nested invocation: {cmd}"
        );
    }

    // ── opencode plugin contract test ─────────────────────────────────────────

    #[test]
    fn opencode_plugin_payload_accepted_by_hook() {
        let _guard = LOCK.lock().unwrap();
        // The plugin sends {"tool_name":"Bash","tool_input":{"command":"<cmd>"}} —
        // the same snake_case shape Claude Code uses. Verify process() intercepts it.
        let cmd = "tkpsql --sql 'SELECT email FROM users'";
        let payload = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": cmd }
        })
        .to_string();
        let config = default_config();
        let out = process(&payload, &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let rewritten = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(
            rewritten.starts_with("gate run -- tkpsql"),
            "plugin payload must produce a rewrite: {rewritten}"
        );
    }

    #[test]
    fn opencode_plugin_template_references_correct_json_keys() {
        let _guard = LOCK.lock().unwrap();
        // Guard against the plugin template drifting away from what hook.rs expects.
        let tmpl = crate::init_opencode::PLUGIN_TEMPLATE;
        assert!(tmpl.contains("tool_name"), "template must send tool_name");
        assert!(tmpl.contains("tool_input"), "template must send tool_input");
        assert!(
            tmpl.contains("hookSpecificOutput"),
            "template must read hookSpecificOutput"
        );
        assert!(
            tmpl.contains("updatedInput"),
            "template must read updatedInput"
        );
    }

    // ── kubectl exec (--) argument-terminator tests ───────────────────────────

    #[test]
    fn kubectl_exec_double_dash_psql_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input("kubectl exec mypod -- psql -c 'SELECT email FROM users'"),
            &config,
        );
        assert!(out.is_some(), "kubectl exec -- psql must be intercepted");
        let v: Value = serde_json::from_str(&out.unwrap()).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run --"), "got: {cmd}");
    }

    #[test]
    fn kubectl_exec_with_namespace_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input("kubectl exec -n production mypod -- psql -c 'SELECT email FROM users'"),
            &config,
        );
        assert!(
            out.is_some(),
            "kubectl exec -n ns pod -- psql must be intercepted"
        );
    }

    #[test]
    fn kubectl_exec_with_it_flags_intercepted() {
        let _guard = LOCK.lock().unwrap();
        let config = default_config();
        let out = process(
            &make_input("kubectl exec -it mypod -- psql -c 'SELECT email FROM users'"),
            &config,
        );
        assert!(
            out.is_some(),
            "kubectl exec -it pod -- psql must be intercepted"
        );
    }

    #[test]
    fn kubectl_exec_double_dash_sh_c_psql_intercepted() {
        let _guard = LOCK.lock().unwrap();
        // Both blind spots combined: -- terminator + sh -c nesting
        let config = default_config();
        let out = process(
            &make_input(r#"kubectl exec mypod -- sh -c "psql -c 'SELECT email FROM users'""#),
            &config,
        );
        assert!(
            out.is_some(),
            "kubectl exec -- sh -c psql must be intercepted"
        );
        let v: Value = serde_json::from_str(&out.unwrap()).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("gate run --"), "got: {cmd}");
    }

    #[test]
    fn kubectl_exec_double_dash_sh_c_skips_json_tool_rewrite() {
        let _guard = LOCK.lock().unwrap();
        let config = make_config(&[("psql", Some("-c"), Some("psql-json"))]);
        let out = process(
            &make_input(r#"kubectl exec mypod -- sh -c "psql -c 'SELECT email FROM users'""#),
            &config,
        );
        assert!(out.is_some(), "must be intercepted");
        let v: Value = serde_json::from_str(&out.unwrap()).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(
            !cmd.contains("psql-json"),
            "must not rewrite to json_tool for nested invocation: {cmd}"
        );
    }
}
