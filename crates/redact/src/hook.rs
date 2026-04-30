use std::io::{self, Read};
use serde_json::{json, Value};

const INTERCEPTED_TOOLS: &[&str] = &["tkpsql", "tkdbr", "mysql", "psql"];

pub fn run() {
    let mut stdin = String::new();
    io::stdin().read_to_string(&mut stdin).unwrap_or_default();
    if let Some(output) = process(&stdin) {
        print!("{}", output);
    }
    // No output = passthrough (Claude Code allows the original command)
}

/// Returns Some(json_string) to rewrite, None to pass through unchanged.
fn process(stdin: &str) -> Option<String> {
    let hook_input: Value = serde_json::from_str(stdin).ok()?;

    let command = hook_input
        .get("tool_input")
        .and_then(|ti| ti.get("command"))
        .and_then(|c| c.as_str())?
        .to_string();

    let tokens = shell_words::split(&command).ok().filter(|t| !t.is_empty())?;

    let basename = std::path::Path::new(&tokens[0])
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&tokens[0])
        .to_string();

    // Loop avoidance: already routed through redact run
    if basename == "redact" && tokens.get(1).map(String::as_str) == Some("run") {
        return None;
    }

    if !INTERCEPTED_TOOLS.contains(&basename.as_str()) {
        return None;
    }

    // Rewrite: preserve all tool_input fields, replace command
    let mut updated_input = hook_input["tool_input"].clone();
    if let Some(obj) = updated_input.as_object_mut() {
        obj.insert("command".to_string(), json!(format!("redact run -- {}", command)));
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        assert!(process(&make_input("ls -la")).is_none());
        assert!(process(&make_input("grep foo bar.txt")).is_none());
    }

    #[test]
    fn rewrite_tkpsql() {
        let out = process(&make_input("tkpsql --sql 'SELECT email FROM users'")).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("redact run -- tkpsql"));
        assert!(cmd.contains("SELECT email FROM users"));
    }

    #[test]
    fn rewrite_mysql() {
        let out = process(&make_input("mysql -e 'SELECT ssn FROM patients'")).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let cmd = v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.starts_with("redact run -- mysql"));
    }

    #[test]
    fn loop_avoidance() {
        // Already a redact run command — must not rewrite again
        assert!(process(&make_input("redact run -- tkpsql --sql 'SELECT 1'")).is_none());
    }

    #[test]
    fn invalid_json_passthrough() {
        assert!(process("not json at all").is_none());
    }

    #[test]
    fn permission_decision_is_allow() {
        let out = process(&make_input("psql -c 'SELECT phone FROM contacts'")).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecision"].as_str().unwrap(),
            "allow"
        );
    }

    #[test]
    fn full_path_basename_matched() {
        // argv[0] with path prefix — basename should still match
        let out = process(&make_input("/usr/local/bin/tkpsql --sql 'SELECT 1'"));
        assert!(out.is_some());
    }
}
