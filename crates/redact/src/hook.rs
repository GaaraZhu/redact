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

/// Returns `Some(json_string)` to rewrite, `None` to pass through unchanged.
fn process(stdin: &str, config: &Config) -> Option<String> {
    let hook_input: Value = serde_json::from_str(stdin).ok()?;

    let command = hook_input
        .get("tool_input")
        .and_then(|ti| ti.get("command"))
        .and_then(|c| c.as_str())?
        .to_string();

    let tokens = shell_words::split(&command)
        .ok()
        .filter(|t| !t.is_empty())?;

    // Skip leading KEY=value env-var assignments (e.g. PGPASSWORD=x psql ...)
    let cmd_token = tokens
        .iter()
        .find(|t| !t.contains('=') || t.starts_with('-'))?;

    let basename = std::path::Path::new(cmd_token)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(cmd_token)
        .to_string();

    // Loop avoidance: already routed through redact run
    if basename == "redact" && tokens.get(1).map(String::as_str) == Some("run") {
        return None;
    }

    let tool_config = config.tools.get(&basename)?;

    // If the tool has a json_tool configured, rewrite the command to use it:
    // replace the binary name and translate the sql_arg flag to --sql.
    let effective_command = match (&tool_config.json_tool, &tool_config.sql_arg) {
        (Some(json_tool), Some(sql_arg)) => {
            rewrite_to_json_tool(&tokens, cmd_token, sql_arg, json_tool)
        }
        _ => command.clone(),
    };

    // Rewrite: preserve all tool_input fields, replace command
    let mut updated_input = hook_input["tool_input"].clone();
    if let Some(obj) = updated_input.as_object_mut() {
        obj.insert(
            "command".to_string(),
            json!(format!("redact run -- {}", effective_command)),
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

/// Rewrite `tokens` so that `cmd_token` is replaced with `json_tool` and
/// `sql_arg` (in both `--flag VALUE` and `--flag=VALUE` forms) is replaced
/// with `--sql`. Returns the reconstructed shell-quoted command string.
fn rewrite_to_json_tool(
    tokens: &[String],
    cmd_token: &str,
    sql_arg: &str,
    json_tool: &str,
) -> String {
    let eq_prefix = format!("{sql_arg}=");
    let new_tokens: Vec<String> = tokens
        .iter()
        .map(|t| {
            if t == cmd_token {
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
    fn passthrough_non_intercepted() {
        let config = default_config();
        assert!(process(&make_input("ls -la"), &config).is_none());
        assert!(process(&make_input("grep foo bar.txt"), &config).is_none());
    }

    #[test]
    fn rewrite_tkpsql() {
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
        assert!(cmd.starts_with("redact run -- tkpsql"));
        assert!(cmd.contains("SELECT email FROM users"));
    }

    #[test]
    fn rewrite_tkdbr() {
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
        assert!(cmd.starts_with("redact run -- tkdbr"));
    }

    #[test]
    fn rewrite_mysql() {
        let config = default_config();
        let out =
            process(&make_input("mysql -e 'SELECT ssn FROM patients'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("redact run -- mysql"));
    }

    #[test]
    fn rewrite_psql() {
        let config = default_config();
        let out = process(&make_input("psql -c 'SELECT phone FROM contacts'"), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("redact run -- psql"));
    }

    #[test]
    fn loop_avoidance() {
        let config = default_config();
        assert!(process(&make_input("redact run -- tkpsql --sql 'SELECT 1'"), &config).is_none());
    }

    #[test]
    fn invalid_json_passthrough() {
        let config = default_config();
        assert!(process("not json at all", &config).is_none());
    }

    #[test]
    fn permission_decision_is_allow() {
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
        let config = default_config();
        assert!(process(
            &make_input("/usr/local/bin/tkpsql --sql 'SELECT 1'"),
            &config
        )
        .is_some());
    }

    #[test]
    fn passthrough_when_tool_not_in_config() {
        let config = make_config(&[]);
        assert!(process(
            &make_input("tkpsql --sql 'SELECT email FROM users'"),
            &config
        )
        .is_none());
    }

    #[test]
    fn command_with_quoted_sql_preserved() {
        let config = default_config();
        let out = process(&make_input(r#"tkpsql --sql "SELECT 'a b' FROM t""#), &config).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("SELECT 'a b'") || cmd.contains(r#"SELECT \'a b\'"#));
    }

    #[test]
    fn malformed_shell_words_passthrough() {
        let config = default_config();
        let input = make_input("tkpsql --sql 'unclosed");
        assert!(process(&input, &config).is_none());
    }

    #[test]
    fn env_var_prefix_intercepted() {
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
        assert!(cmd.starts_with("redact run -- PGPASSWORD=secret psql"));
    }

    #[test]
    fn multiple_env_vars_intercepted() {
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

    // ── json_tool rewrite tests ───────────────────────────────────────────────

    #[test]
    fn json_tool_rewrites_binary_and_flag() {
        let config = make_config(&[("psql", Some("-c"), Some("psql-json"))]);
        let out = process(
            &make_input("psql -c 'SELECT email FROM users'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        // Binary replaced and flag translated
        assert!(cmd.contains("psql-json"), "expected psql-json in: {cmd}");
        assert!(cmd.contains("--sql"), "expected --sql in: {cmd}");
        assert!(!cmd.contains("psql-json-json"), "double-rewrite guard: {cmd}");
    }

    #[test]
    fn json_tool_flag_equals_form() {
        let config = make_config(&[("psql", Some("-c"), Some("psql-json"))]);
        let out = process(
            &make_input("psql -c='SELECT id FROM t'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("--sql="), "expected --sql= in: {cmd}");
    }

    #[test]
    fn json_tool_preserves_env_var_prefix() {
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
        let config = make_config(&[("mysql", Some("-e"), Some("mysql-json"))]);
        let out = process(
            &make_input("mysql -e 'SELECT email FROM users'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("mysql-json"), "expected mysql-json in: {cmd}");
        assert!(cmd.contains("--sql"), "expected --sql in: {cmd}");
    }

    #[test]
    fn json_tool_sqlcmd_rewrite() {
        let config = make_config(&[("sqlcmd", Some("-Q"), Some("sqlcmd-json"))]);
        let out = process(
            &make_input("sqlcmd -Q 'SELECT email FROM users'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("sqlcmd-json"), "expected sqlcmd-json in: {cmd}");
        assert!(cmd.contains("--sql"), "expected --sql in: {cmd}");
    }

    #[test]
    fn no_json_tool_uses_original_command() {
        // Tool in config but no json_tool: original command passed to redact run unchanged
        let config = make_config(&[("psql", Some("-c"), None)]);
        let out = process(
            &make_input("psql -c 'SELECT id FROM t'"),
            &config,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("redact run -- psql"), "unexpected cmd: {cmd}");
        assert!(!cmd.contains("psql-json"), "should not rewrite: {cmd}");
    }
}
